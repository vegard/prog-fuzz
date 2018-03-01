// Copyright (C) 2017  Vegard Nossum <vegard.nossum@oracle.com>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <fcntl.h>
#include <error.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <queue>
#include <random>
#include <set>
#include <vector>

// From AFL
#include "config.h"

struct node;
typedef std::shared_ptr<node> node_ptr;

// Internal representation of a (sub)program; either
// (a) a fixed string, OR (b) a sequence of child nodes
struct node {
	std::string text;
	std::vector<node_ptr> children;

	// Fixed means the node cannot be replaced through mutation
	bool fixed;

	node():
		fixed(false)
	{
	}

	node(std::string text, bool fixed = false):
		text(text),
		fixed(fixed)
	{
	}

	explicit node(const std::vector<node_ptr> &children):
		children(children),
		fixed(false)
	{
	}

	virtual ~node()
	{
	}

	node_ptr set_child(unsigned int i, node_ptr x) const
	{
		auto ret = std::make_shared<node>(children);
		ret->children[i] = x;
		return ret;
	}

	void print(FILE *f) const
	{
		fprintf(f, "%s", text.c_str());
		for (const auto &child: children)
			child->print(f);
	}

	// textual size when flattened (may be used to score test cases)
	unsigned int size() const
	{
		unsigned int n = text.size();
		for (const auto &child: children)
			n += child->size();
		return n;
	}
};

static node_ptr replace(node_ptr n, node_ptr a, node_ptr b)
{
	if (n == a)
		return b;

	const auto &children = n->children;
	for (unsigned int i = 0; i < children.size(); ++i) {
		node_ptr child = children[i];
		node_ptr child2 = replace(children[i], a, b);
		if (child2 != child) {
			n = n->set_child(i, child2);
			// If we assume one occurrence only, we can skip the other children
			break;
		}
	}

	return n;
}

static std::vector<node_ptr> find_leaves(node_ptr root)
{
	std::vector<node_ptr> result;

	// Bog standard agenda-based traversal
	std::set<node_ptr> seen;
	std::set<node_ptr> todo;
	todo.insert(root);

	while (todo.size()) {
		auto it = todo.begin();
		node_ptr n = *it;
		assert(n);
		todo.erase(it);
		if (!seen.insert(n).second)
			continue;

		const auto &children = n->children;
		if (!children.size() && !n->fixed)
			result.push_back(n);

		for (const auto &child: children)
			todo.insert(child);
	}

	return result;
}

#include "rules/cxx.hh"

static std::random_device r;
static std::default_random_engine re;

struct testcase {
	node_ptr root;
	unsigned int generation;
	std::set<unsigned int> mutations;
	unsigned int mutation_counter;
	unsigned int new_bits;
	float score;

	explicit testcase(node_ptr root, unsigned int generation, std::set<unsigned int> mutations, unsigned int mutation_counter, unsigned int new_bits):
		root(root),
		generation(generation),
		mutation_counter(mutation_counter),
		new_bits(new_bits)
	{
		// the lower score, the more important the testcase is
		score = 0;

		score -= mutations.size();

#if 1
		// We want test cases to grow in size until they reach a
		// certain number of bytes, then we try to keep them there.
		//
		// Too large test cases slow everything down, but new mutations
		// tend to make them bigger.
		const unsigned int max_size = 2048;
		unsigned int size = root->size();
		score += ((size < max_size) ? max_size : size - max_size) / 5;
#endif

		score += -(int) generation;

		// if a mutation has been used few times, we give the score a boost
		score -= 2. * (mutation_counter + 1) / mutation_counter;

		// trace bits from AFL are very important
		score += -10 * (int) new_bits;

		// add a small random offset
		score += std::normal_distribution<>(0, 100)(re);
	}
};

bool operator<(const testcase &a, const testcase &b)
{
	if (a.score < b.score)
		return true;

	return a.root < b.root;
}

// Fixed-size priority queue that discards deprioritized items when full
template<typename T>
struct fixed_priority_queue
{
	std::set<T> set;
	unsigned int fixed_size;

	fixed_priority_queue(unsigned int size):
		fixed_size(size)
	{
	}

	void push(const T& x)
	{
		set.insert(x);

		unsigned int n = set.size();
		for (unsigned int i = fixed_size; i < n; ++i)
			set.erase(--set.end());
	}

	const T top()
	{
		return *set.begin();
	}

	const T pop()
	{
		auto it = set.begin();
		T result = *it;
		set.erase(it);
		return result;
	}

	unsigned int size()
	{
		return set.size();
	}

	bool empty()
	{
		return set.empty();
	}
};

// From AFL
int shm_id;
uint8_t *trace_bits;

// From AFL
static void remove_shm(void)
{
	if (shmctl(shm_id, IPC_RMID, NULL) == -1)
		error(EXIT_FAILURE, errno, "shmctl(IPC_RMID)");
	if (shmdt(trace_bits) == -1)
		error(EXIT_FAILURE, errno, "shmdt()");
}

// From AFL
static void setup_shm(void)
{
	shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
	if (shm_id < 0)
		error(EXIT_FAILURE, errno, "shmget()");

	atexit(remove_shm);

	char *shm_str;
	asprintf(&shm_str, "%d", shm_id);
	setenv(SHM_ENV_VAR, shm_str, 1);
	free(shm_str);

	trace_bits = (uint8_t *) shmat(shm_id, NULL, 0);
	if (!trace_bits)
		error(EXIT_FAILURE, errno, "shmat()");
}

int main(int argc, char *argv[])
{
	re = std::default_random_engine(r());

	int devnull = open("/dev/null", O_RDWR);
	if (devnull == -1)
		error(EXIT_FAILURE, errno, "/dev/null: open()");

	FILE *devnullf = fdopen(devnull, "r+");
	if (!devnullf)
		error(EXIT_FAILURE, errno, "/dev/null: fdopen()");

	unsigned int mutation_counters[nr_mutations] = {};
	unsigned int trace_bits_counters[MAP_SIZE] = {};

	fixed_priority_queue<testcase> pq(1200);

	unsigned int nr_execs = 0;
	while (true) {
#if 0
		printf("queue: ");
		for (const auto &t: pq.set)
			printf("%.2f ", t.score);
		printf("\n");
#endif

#if 1 // periodically resetting (restarting) everything seems beneficial for now; interesting future angle WRT SAT solver restarts
		if (nr_execs % 2500 == 0) {
			pq = fixed_priority_queue<testcase>(1200);
			for (unsigned int i = 0; i < nr_mutations; ++i)
				mutation_counters[i] = 0;
			for (unsigned int i = 0; i < MAP_SIZE; ++i)
				trace_bits_counters[i] = 0;
		}
#endif

		if (pq.empty() || std::uniform_real_distribution<>(0, 1)(re) < 0) {
			// (re)seed/(re)initialise
			pq.push(testcase(std::make_shared<node>(), 0, std::set<unsigned int>(), 1, 0));
		}

		// I tried occasionally pop()ing the testcase but it tends to
		// completely drain the queue even when we're working on something
		// that seems fairly promising.
		//auto current = (std::uniform_real_distribution<>(0, 1)(re) < .999999) ? pq.top() : pq.pop();
		auto current = pq.top();

		auto leaves = find_leaves(current.root);
		if (leaves.size() == 0) {
			pq.pop();
			continue;
		}

		// TODO: apply more than 1 mutation at a time
		auto leaf = leaves[std::uniform_int_distribution<int>(0, leaves.size() - 1)(re)];
		unsigned int mutation = std::uniform_int_distribution<int>(0, nr_mutations - 1)(re);
		auto root = mutate(current.root, leaf, mutation);

		int pipefd[2];
		if (pipe2(pipefd, 0) == -1)
			error(EXIT_FAILURE, errno, "pipe2()");

		setup_shm();

		pid_t child = fork();
		if (child == -1)
			error(EXIT_FAILURE, errno, "fork()");

		if (child == 0) {
			close(pipefd[1]);
			dup2(pipefd[0], STDIN_FILENO);
			close(pipefd[0]);
			dup2(devnull, STDOUT_FILENO);

			int stderr_fd = open("/tmp/stderr.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (stderr_fd == -1)
				error(EXIT_FAILURE, errno, "open()");

			dup2(stderr_fd, STDERR_FILENO);

			// TODO: clean up, take from command line
			//
			// exec() the compiler. You need to substitute the path to your own compiler here.

			//if (execlp("/usr/bin/g++-5", "g++", "-x", "c++", "-std=c++14", "-Os", "-c", "-", NULL) == -1)
			//if (execlp("/home/vegard/personal/programming/gcc/build/gcc/xgcc", "xgcc", "-x", "c++", "-std=c++14", "-O3", "-c", "-", NULL) == -1)
			//if (execlp("/home/vegard/personal/programming/gcc/build/gcc/xgcc", "xgcc", "-x", "c++", "-std=c++14", "-O3", "-Wall", "-fpermissive", "-g", "-pg", "-fwhole-program", "-ftree-pre", "-fstack-protector-all", "-fsanitize=undefined", "-fsanitize=address", "-fsanitize=leak", "-c", "-", NULL) == -1)
			//if (execlp("/home/vegard/personal/programming/gcc/build/gcc/xgcc", "xgcc", "-x", "c++", "-std=c++14", "-O3", "-Wall", "-fpermissive", "-g", "-pg", "-fwhole-program", "-ftree-pre", "-fstack-protector-all", "-fsanitize=undefined", "-fsanitize=address", "-fsanitize=leak", "-S", "-", NULL) == -1)
			// invoke cc1plus directly (skips fork+exec)
			if (execlp("/home/vegard/personal/programming/gcc/build/gcc/cc1plus", "cc1plus", "-quiet", "-imultiarch", "x86_64-linux-gnu", "-iprefix", "/home/vegard/personal/programming/gcc/build/gcc/../lib/gcc/x86_64-pc-linux-gnu/8.0.1/", "-D_GNU_SOURCE", "-", "-quiet", "-dumpbase", "-", "-mtune=generic", "-march=x86-64", "-auxbase", "-", "-g", "-O3", "-Wall", "-std=c++14", "-p", "-fpermissive", "-fwhole-program", "-ftree-pre", "-fstack-protector-all", /*"-fsanitize=undefined",*/ "-fsanitize=address", "-fsanitize=leak", "-faggressive-loop-optimizations", "-fauto-inc-dec", "-fbranch-probabilities", "-fbranch-target-load-optimize2", "-fcheck-data-deps", "-fcompare-elim", "-fdce", "-fdse", "-fexpensive-optimizations", "-fhoist-adjacent-loads", "-fgcse-lm", "-fgcse-sm", "-fipa-profile", "-fno-toplevel-reorder", "-fsched-group-heuristic", "-fschedule-fusion", "-fschedule-insns", "-fschedule-insns2", "-ftracer", "-funroll-loops", "-fvect-cost-model", "-o", "-.s", NULL) == -1)
				error(EXIT_FAILURE, errno, "execvp()");
		}

		close(pipefd[0]);
		FILE *f = fdopen(pipefd[1], "w");
		if (!f)
			error(EXIT_FAILURE, errno, "fdopen()");
		root->print(f);
		fclose(f);

		int status;
		while (true) {
			pid_t kid = waitpid(child, &status, 0);
			if (kid == -1) {
				if (errno == EINTR || errno == EAGAIN)
					continue;
				error(EXIT_FAILURE, errno, "waitpid()");
			}

			if (kid != child)
				error(EXIT_FAILURE, 0, "kid != child");

			if (WIFEXITED(status) || WIFSIGNALED(status))
				break;
		}

		++nr_execs;

		if (WIFSIGNALED(status)) {
#if 0 // Ignore segfaults for now, have to wait for a fix for https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84576
			printf("signal %d:\n", WTERMSIG(status));
			root->print(stdout);
			printf("\n");

			FILE *fp = fopen("/tmp/random.cc", "w");
			if (!fp)
				error(EXIT_FAILURE, errno, "fopen()");
			root->print(fp);
			fclose(fp);
			break;
#else
			//pq.pop();
#endif
		}

		{
			FILE *f = fopen("/tmp/stderr.txt", "r");
			if (!f)
				error(EXIT_FAILURE, errno, "fopen()");

			static char buffer[10 * 4096];
			size_t len = fread(buffer, 1, sizeof(buffer), f);
			fclose(f);

			if (len > 0) {
				buffer[len - 1] = '\0';

				// Check for ICEs, but ignore a set of specific ones which we've
				// already reported and which keep showing up.
				if (strstr(buffer, "internal compiler error") && !strstr(buffer, "types may not be defined in parameter types") && !strstr(buffer, "internal compiler error: in synthesize_implicit_template_parm") && !strstr(buffer, "internal compiler error: in search_anon_aggr") && !strstr(buffer, "non_type_check") && !strstr(buffer, "internal compiler error: in xref_basetypes, at") && !strstr(buffer, "internal compiler error: in build_capture_proxy") && !strstr(buffer, "internal compiler error: tree check: expected record_type or union_type or qual_union_type, have array_type in reduced_constant_expression_p")) {
					struct timeval tv;
					if (gettimeofday(&tv, 0) == -1)
						error(EXIT_FAILURE, errno, "gettimeofday()");

					printf("ICE:\n");
					root->print(stdout);
					printf("\n");

					char filename[PATH_MAX];
					snprintf(filename, sizeof(filename), "output/%lu.cc", tv.tv_sec);
					printf("Writing reproducer to %s\n", filename);

					FILE *fp = fopen(filename, "w");
					if (!fp)
						error(EXIT_FAILURE, errno, "fopen()");
					root->print(fp);
					fclose(fp);

					fwrite(buffer, 1, len, stdout);
					remove_shm();
					break;
				}
			}
		}

		int success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
		if (success) {
			// Found new bits in AFL instrumentation?
			unsigned int new_bits = 0;
			for (unsigned int i = 0; i < MAP_SIZE; ++i) {
				if (trace_bits[i]) {
					if (++trace_bits_counters[i] == 1)
						++new_bits;
				}
			}

			auto mutations = current.mutations;
			mutations.insert(mutation);
			testcase new_testcase(root, current.generation + 1, mutations, current.mutation_counter + ++mutation_counters[mutation], current.new_bits + new_bits);

			printf("\e[31mcompiled (%u | score %.2f | %u | %u): \e[0m", nr_execs, new_testcase.score, pq.size(), new_bits);
			root->print(stdout);
			printf("\n");

			pq.push(new_testcase);
		}

		remove_shm();
	}

	return 0;
}
