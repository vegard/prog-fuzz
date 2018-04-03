// Copyright (C) 2018  Vegard Nossum <vegard.nossum@oracle.com>

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
#include <sstream>
#include <vector>

// From AFL
#include "config.h"

struct type;
typedef std::shared_ptr<type> type_ptr;

struct expression;
typedef std::shared_ptr<expression> expr_ptr;
typedef std::vector<expr_ptr> expr_vec;

struct function;
typedef std::shared_ptr<function> function_ptr;

struct program;
typedef std::shared_ptr<program> program_ptr;

struct visitor {
	unsigned int unreachable_counter;

	visitor():
		unreachable_counter(0)
	{
	}

	void enter_unreachable()
	{
		++unreachable_counter;
	}

	void leave_unreachable()
	{
		--unreachable_counter;
	}

	bool is_unreachable()
	{
		return unreachable_counter > 0;
	}

	virtual void visit(type_ptr &) {}
	virtual void visit(function_ptr fn, expr_ptr &) {}
	virtual void visit(function_ptr fn, function_ptr &) {}
};

struct type {
	std::string name;

	type(std::string name):
		name(name)
	{
	}

	virtual ~type()
	{
	}

	void print(FILE *f)
	{
		fprintf(f, "%s", name.c_str());
	}
};

static type_ptr void_type = std::make_shared<type>("void");
static type_ptr voidp_type = std::make_shared<type>("void *");
static type_ptr int_type = std::make_shared<type>("int");

struct expression {
	unsigned int generation;

	expression(unsigned int generation):
		generation(generation)
	{
	}

	virtual ~expression()
	{
	}

	virtual expr_ptr clone(expr_ptr &this_ptr) = 0;

	virtual void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.visit(fn, this_ptr);
	}

	virtual void print(FILE *f, unsigned int indent) = 0;
};

// Helper to maintain reachability information when traversing AST
struct unreachable_expression: expression {
	expr_ptr expr;

	unreachable_expression(unsigned int generation, expr_ptr expr):
		expression(generation),
		expr(expr)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return std::make_shared<unreachable_expression>(generation, expr->clone(expr));
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.enter_unreachable();
		v.visit(fn, this_ptr);
		expr->visit(fn, expr, v);
		v.leave_unreachable();
	}

	void print(FILE *f, unsigned int indent)
	{
		expr->print(f, indent);
	}
};

struct variable_expression: expression {
	// TODO: should we have a separate class variable as well?
	std::string name;

	variable_expression(unsigned int generation, std::string name):
		expression(generation),
		name(name)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return this_ptr;
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "%s", name.c_str());
	}
};

struct int_literal_expression: expression {
	int value;

	int_literal_expression(unsigned int generation, int value):
		expression(generation),
		value(value)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return this_ptr;
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "%d", value);
	}
};

struct cast_expression: expression {
	type_ptr type;
	expr_ptr expr;

	cast_expression(unsigned int generation, type_ptr type, expr_ptr expr):
		expression(generation),
		type(type),
		expr(expr)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return std::make_shared<cast_expression>(generation, type, expr->clone(expr));
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.visit(fn, this_ptr);

		expr->visit(fn, expr, v);
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "(");
		type->print(f);
		fprintf(f, ") (");
		expr->print(f, indent);
		fprintf(f, ")");
	}
};

struct call_expression: expression {
	expr_ptr fn_expr;
	std::vector<expr_ptr> arg_exprs;

	call_expression(unsigned int generation, expr_ptr fn_expr, std::initializer_list<expr_ptr> arg_exprs = {}):
		expression(generation),
		fn_expr(fn_expr),
		arg_exprs(arg_exprs)
	{
	}

	call_expression(unsigned int generation, expr_ptr fn_expr, std::vector<expr_ptr> arg_exprs):
		expression(generation),
		fn_expr(fn_expr),
		arg_exprs(arg_exprs)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		std::vector<expr_ptr> new_arg_exprs;
		for (auto &arg_expr: arg_exprs)
			new_arg_exprs.push_back(arg_expr->clone(arg_expr));

		return std::make_shared<call_expression>(generation, fn_expr->clone(fn_expr), new_arg_exprs);
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.visit(fn, this_ptr);

		fn_expr->visit(fn, fn_expr, v);
		for (auto &arg_expr: arg_exprs)
			arg_expr->visit(fn, arg_expr, v);
	}

	void print(FILE *f, unsigned int indent)
	{
		fn_expr->print(f, indent);
		fprintf(f, "(");

		for (unsigned int i = 0; i < arg_exprs.size(); ++i) {
			if (i > 0)
				fprintf(f, ", ");

			arg_exprs[i]->print(f, indent);
		}

		fprintf(f, ")");
	}
};

struct preop_expression: expression {
	std::string op;
	expr_ptr arg;

	preop_expression(unsigned int generation, std::string op, expr_ptr arg):
		expression(generation),
		op(op),
		arg(arg)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return std::make_shared<preop_expression>(generation, op, arg->clone(arg));
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.visit(fn, this_ptr);

		arg->visit(fn, arg, v);
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "%s(", op.c_str());
		arg->print(f, indent);
		fprintf(f, ")");
	}
};

struct binop_expression: expression {
	std::string op;
	expr_ptr lhs;
	expr_ptr rhs;

	binop_expression(unsigned int generation, std::string op, expr_ptr lhs, expr_ptr rhs):
		expression(generation),
		op(op),
		lhs(lhs),
		rhs(rhs)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return std::make_shared<binop_expression>(generation, op, lhs->clone(lhs), rhs->clone(rhs));
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.visit(fn, this_ptr);

		lhs->visit(fn, lhs, v);
		rhs->visit(fn, rhs, v);
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "(");
		lhs->print(f, indent);
		fprintf(f, ") %s (", op.c_str());
		rhs->print(f, indent);
		fprintf(f, ")");
	}
};

struct ternop_expression: expression {
	std::string op1;
	std::string op2;
	expr_ptr arg1;
	expr_ptr arg2;
	expr_ptr arg3;

	ternop_expression(unsigned int generation, std::string op1, std::string op2, expr_ptr arg1, expr_ptr arg2, expr_ptr arg3):
		expression(generation),
		op1(op1),
		op2(op2),
		arg1(arg1),
		arg2(arg2),
		arg3(arg3)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return std::make_shared<ternop_expression>(generation, op1, op2, arg1->clone(arg1), arg2->clone(arg2), arg3->clone(arg3));
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.visit(fn, this_ptr);

		arg1->visit(fn, arg1, v);
		arg2->visit(fn, arg2, v);
		arg3->visit(fn, arg3, v);
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "(");
		arg1->print(f, indent);
		fprintf(f, ") %s (", op1.c_str());
		arg2->print(f, indent);
		fprintf(f, ") %s (", op2.c_str());
		arg3->print(f, indent);
		fprintf(f, ")");
	}
};

struct unreachable_statement: expression {
	expr_ptr stmt;

	unreachable_statement(unsigned int generation, expr_ptr stmt):
		expression(generation),
		stmt(stmt)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return std::make_shared<unreachable_statement>(generation, stmt->clone(stmt));
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.enter_unreachable();
		v.visit(fn, this_ptr);
		stmt->visit(fn, stmt, v);
		v.leave_unreachable();
	}

	void print(FILE *f, unsigned int indent)
	{
		stmt->print(f, indent);
	}
};

typedef expression statement;

struct declaration_statement: statement {
	type_ptr var_type;
	expr_ptr var_expr;
	expr_ptr value_expr;

	declaration_statement(unsigned int generation, type_ptr var_type, expr_ptr var_expr, expr_ptr value_expr):
		expression(generation),
		var_type(var_type),
		var_expr(var_expr),
		value_expr(value_expr)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return std::make_shared<declaration_statement>(generation, var_type, var_expr->clone(var_expr), value_expr->clone(value_expr));
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.visit(fn, this_ptr);

		//var_type->visit(fn, var_type, v);
		var_expr->visit(fn, var_expr, v);
		value_expr->visit(fn, value_expr, v);
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "%*s", 2 * indent, "");
		var_type->print(f);
		fprintf(f, " ");
		var_expr->print(f, indent);
		fprintf(f, " = ");
		value_expr->print(f, indent);
		fprintf(f, ";\n");
	}
};

struct return_statement: statement {
	expr_ptr ret_expr;

	return_statement(unsigned int generation, expr_ptr ret_expr):
		expression(generation),
		ret_expr(ret_expr)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return std::make_shared<return_statement>(generation, ret_expr->clone(ret_expr));
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.visit(fn, this_ptr);

		ret_expr->visit(fn, ret_expr, v);
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "%*sreturn ", 2 * indent, "");
		ret_expr->print(f, indent);
		fprintf(f, ";\n");
	}
};

struct block_statement: statement {
	std::vector<expr_ptr> statements;

	explicit block_statement(unsigned int generation):
		expression(generation)
	{
	}

	explicit block_statement(unsigned int generation, std::vector<expr_ptr> &statements):
		expression(generation),
		statements(statements)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		std::vector<expr_ptr> new_statements;
		for (auto &stmt: statements)
			new_statements.push_back(stmt->clone(stmt));

		return std::make_shared<block_statement>(generation, new_statements);
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.visit(fn, this_ptr);

		for (auto &stmt: statements)
			stmt->visit(fn, stmt, v);
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "{\n");
		for (const auto &stmt: statements)
			stmt->print(f, indent + 1);
		fprintf(f, "%*s}\n", 2 * (indent - 1), "");
	}
};

struct if_statement: statement {
	expr_ptr cond_expr;
	expr_ptr true_stmt;
	expr_ptr false_stmt;

	if_statement(unsigned int generation, expr_ptr cond_expr, expr_ptr true_stmt, expr_ptr false_stmt):
		expression(generation),
		cond_expr(cond_expr),
		true_stmt(true_stmt),
		false_stmt(false_stmt)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return std::make_shared<if_statement>(generation, cond_expr->clone(cond_expr), true_stmt->clone(true_stmt), false_stmt ? false_stmt->clone(false_stmt) : false_stmt);
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.visit(fn, this_ptr);

		cond_expr->visit(fn, cond_expr, v);
		true_stmt->visit(fn, true_stmt, v);
		false_stmt->visit(fn, false_stmt, v);
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "%*s", 2 * indent, "");
		fprintf(f, "if (");
		cond_expr->print(f, indent);
		fprintf(f, ") ");
		true_stmt->print(f, indent + 1);

		if (false_stmt) {
			fprintf(f, "%*selse ", 2 * indent, "");
			false_stmt->print(f, indent + 1);
		}
	}
};

struct asm_constraint_expression: expression {
	std::string constraint;
	expr_ptr expr;

	asm_constraint_expression(unsigned int generation, std::string constraint, expr_ptr expr):
		expression(generation),
		constraint(constraint),
		expr(expr)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return std::make_shared<asm_constraint_expression>(generation, constraint, expr->clone(expr));
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.visit(fn, this_ptr);

		expr->visit(fn, expr, v);
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "\"%s\" (", constraint.c_str());
		expr->print(f, indent);
		fprintf(f, ")");
	}
};

struct asm_statement: statement {
	bool is_volatile;
	std::vector<expr_ptr> outputs;
	std::vector<expr_ptr> inputs;

	asm_statement(unsigned int generation, bool is_volatile, std::vector<expr_ptr> outputs, std::vector<expr_ptr> inputs):
		expression(generation),
		is_volatile(is_volatile),
		outputs(outputs),
		inputs(inputs)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		std::vector<expr_ptr> new_outputs;
		for (auto &output_expr: outputs)
			new_outputs.push_back(output_expr->clone(output_expr));

		std::vector<expr_ptr> new_inputs;
		for (auto &input_expr: inputs)
			new_inputs.push_back(input_expr->clone(input_expr));

		return std::make_shared<asm_statement>(generation, is_volatile, new_outputs, new_inputs);
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.visit(fn, this_ptr);
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "%*s", 2 * indent, "");
		fprintf(f, "asm %s(\"\"", is_volatile ? "volatile " : "");

		if (outputs.size() || inputs.size()) {
			fprintf(f, " : ");

			for (unsigned int i = 0; i < outputs.size(); ++i) {
				if (i > 0)
					fprintf(f, ", ");

				outputs[i]->print(f, indent);
			}
		}

		if (inputs.size()) {
			fprintf(f, " : ");

			for (unsigned int i = 0; i < inputs.size(); ++i) {
				if (i > 0)
					fprintf(f, ", ");

				inputs[i]->print(f, indent);
			}
		}

		fprintf(f, ");\n");
	}
};

struct statement_expression: expression {
	expr_ptr block_stmt;
	expr_ptr last_stmt;

	statement_expression(unsigned int generation, expr_ptr block_stmt, expr_ptr last_stmt):
		expression(generation),
		block_stmt(block_stmt),
		last_stmt(last_stmt)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return std::make_shared<statement_expression>(generation, block_stmt->clone(block_stmt), last_stmt->clone(last_stmt));
	}

	void visit(function_ptr fn, expr_ptr &this_ptr, visitor &v)
	{
		v.visit(fn, this_ptr);

		block_stmt->visit(fn, block_stmt, v);
		last_stmt->visit(fn, last_stmt, v);
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "({ ");
		block_stmt->print(f, 0);
		last_stmt->print(f, 0);
		fprintf(f, "})");
	}
};

struct expression_statement: statement {
	expr_ptr expr;

	expression_statement(unsigned int generation, expr_ptr expr):
		expression(generation),
		expr(expr)
	{
	}

	expr_ptr clone(expr_ptr &this_ptr)
	{
		return std::make_shared<expression_statement>(generation, expr->clone(expr));
	}

	void visit(function_ptr fn, expr_ptr &this_stmt, visitor &v)
	{
		v.visit(fn, this_stmt);

		expr->visit(fn, expr, v);
	}

	void print(FILE *f, unsigned int indent)
	{
		fprintf(f, "%*s", 2 * indent, "");
		expr->print(f, indent);
		fprintf(f, ";\n");
	}
};

struct function {
	std::string name;

	type_ptr return_type;
	std::vector<type_ptr> arg_types;

	expr_ptr body;

	function(std::string name, type_ptr return_type, std::vector<type_ptr> arg_types, expr_ptr body):
		name(name),
		return_type(return_type),
		arg_types(arg_types),
		body(body)
	{
	}

	function_ptr clone()
	{
		return std::make_shared<function>(name, return_type, arg_types, body->clone(body));
	}

	void visit(function_ptr fn, function_ptr &this_ptr, visitor &v)
	{
		v.visit(this_ptr, this_ptr);

		body->visit(this_ptr, body, v);
	}

	void print(FILE *f)
	{
		return_type->print(f);
		fprintf(f, " %s(", name.c_str());
		for (unsigned int i = 0; i < arg_types.size(); ++i) {
			if (i > 0)
				fprintf(f, ", ");

			arg_types[i]->print(f);
		}
		fprintf(f, ")\n");
		body->print(f, 1);
		fprintf(f, "\n");
	}
};

struct ident_allocator {
	unsigned int id;

	ident_allocator():
		id(0)
	{
	}

	std::string new_ident()
	{
		std::ostringstream ss;
		ss << "id" << id++;
		return ss.str();
	}
};

struct program {
	unsigned int generation;

	int toplevel_value;

	ident_allocator ids;

	std::vector<expr_ptr> toplevel_decls;
	std::vector<function_ptr> toplevel_fns;

	function_ptr toplevel_fn;
	expr_ptr toplevel_call_expr;

	explicit program(int toplevel_value):
		generation(0),
		toplevel_value(toplevel_value)
	{
		auto body = std::make_shared<block_statement>(generation);
		body->statements.push_back(std::make_shared<return_statement>(generation, std::make_shared<int_literal_expression>(generation, toplevel_value)));
		toplevel_fn = std::make_shared<function>(ids.new_ident(), int_type, std::vector<type_ptr>(), body);
		toplevel_call_expr = std::make_shared<call_expression>(generation, std::make_shared<variable_expression>(generation, toplevel_fn->name));
	}

	program(unsigned int generation, int toplevel_value, ident_allocator &ids, std::vector<expr_ptr> toplevel_decls, std::vector<function_ptr> toplevel_fns, function_ptr toplevel_fn, expr_ptr toplevel_call_expr):
		generation(generation),
		toplevel_value(toplevel_value),
		ids(ids),
		toplevel_decls(toplevel_decls),
		toplevel_fns(toplevel_fns),
		toplevel_fn(toplevel_fn),
		toplevel_call_expr(toplevel_call_expr)
	{
	}

	program_ptr clone()
	{
		std::vector<expr_ptr> new_toplevel_decls;
		for (auto &stmt_ptr: toplevel_decls)
			new_toplevel_decls.push_back(stmt_ptr->clone(stmt_ptr));

		std::vector<function_ptr> new_toplevel_fns;
		for (auto &fn_ptr: toplevel_fns)
			new_toplevel_fns.push_back(fn_ptr->clone());

		return std::make_shared<program>(generation + 1, toplevel_value, ids, new_toplevel_decls, new_toplevel_fns, toplevel_fn->clone(), toplevel_call_expr->clone(toplevel_call_expr));
	}

	void visit(visitor &v)
	{
		for (auto &stmt_ptr: toplevel_decls)
			stmt_ptr->visit(nullptr, stmt_ptr, v);

		for (auto &fn_ptr: toplevel_fns)
			fn_ptr->visit(nullptr, fn_ptr, v);

		toplevel_fn->visit(nullptr, toplevel_fn, v);
		// XXX? toplevel_call_expr->visit(nullptr, toplevel_call_expr, v);
	}

	void print(FILE *f)
	{
		//fprintf(f, "#include <stdio.h>\n");
		fprintf(f, "extern \"C\" {\n");
		fprintf(f, "extern int printf (const char *__restrict __format, ...);\n");
		fprintf(f, "}\n");
		fprintf(f, "\n");

		for (auto &stmt_ptr: toplevel_decls)
			stmt_ptr->print(f, 0);

		for (auto &fn_ptr: toplevel_fns)
			fn_ptr->print(f);

		toplevel_fn->print(f);

		fprintf(f, "int main(int argc, char *argv[])\n");
		fprintf(f, "{\n");
		fprintf(f, "  printf(\"%%d\\n\", ");
		toplevel_call_expr->print(f, 0);
		fprintf(f, ");\n");
		fprintf(f, "}\n");
	}
};

// Mutation

static std::random_device r;
static std::default_random_engine re;

// Tree traversal helpers

template<typename T>
struct find_result {
	function_ptr fn;
	expr_ptr *expr_ptr_ref;
	std::shared_ptr<T> expr;

	find_result(function_ptr fn, expr_ptr &expr_ptr_ref, std::shared_ptr<T> expr):
		fn(fn),
		expr_ptr_ref(&expr_ptr_ref),
		expr(expr)
	{
	}

	// sort by generation in descending order (used for picking more recently modified expressions)
	bool operator<(const find_result &other) const
	{
		return expr->generation > other.expr->generation;
	}
};

template<typename T>
std::vector<find_result<T>> find_exprs(program_ptr p)
{
	std::vector<find_result<T>> result;

	struct find_exprs_visitor: visitor {
		std::vector<find_result<T>> &result;

		find_exprs_visitor(std::vector<find_result<T>> &result):
			result(result)
		{
		}

		void visit(function_ptr fn, expr_ptr &e)
		{
			// Only return expressions within functions
			if (!fn)
				return;

			auto cast_e = std::dynamic_pointer_cast<T>(e);
			if (cast_e)
				result.push_back(find_result<T>(fn, e, cast_e));
		}
	};

	find_exprs_visitor v(result);
	p->visit(v);
	return result;
}

// parameter to the geometric distribution we use to pick expressions to mutate
static const double find_p = .1;

template<typename T>
std::vector<find_result<T>> find_expr(program_ptr p)
{
	auto results = find_exprs<T>(p);
	if (results.empty())
		return results;

	std::sort(results.begin(), results.end());

	unsigned int index = std::geometric_distribution<unsigned int>(find_p)(re);
	if (index >= results.size())
		index = results.size() - 1;

	std::vector<find_result<T>> new_results;
	new_results.push_back(results[index]);
	return new_results;
}

template<typename T>
struct find_stmts_result {
	function_ptr fn;
	expr_ptr *stmt_ptr_ref;
	std::shared_ptr<T> stmt;

	find_stmts_result(function_ptr fn, expr_ptr &stmt_ptr_ref, std::shared_ptr<T> stmt):
		fn(fn),
		stmt_ptr_ref(&stmt_ptr_ref),
		stmt(stmt)
	{
	}

	// sort by generation in descending order (used for picking more recently modified expressions)
	bool operator<(const find_stmts_result &other) const
	{
		return stmt->generation > other.stmt->generation;
	}
};

// TODO: merge this with find_expr() above...
template<typename T>
std::vector<find_stmts_result<T>> find_stmts(program_ptr p, std::function<bool(visitor &)> filter = [](visitor &){ return true; })
{
	std::vector<find_stmts_result<T>> result;

	struct find_stmts_visitor: visitor {
		std::function<bool(visitor &)> filter;
		std::vector<find_stmts_result<T>> &result;

		find_stmts_visitor(std::function<bool(visitor &)> filter, std::vector<find_stmts_result<T>> &result):
			filter(filter),
			result(result)
		{
		}

		void visit(function_ptr fn, expr_ptr &s)
		{
			if (!filter(*this))
				return;

			auto cast_s = std::dynamic_pointer_cast<T>(s);
			if (cast_s)
				result.push_back(find_stmts_result<T>(fn, s, cast_s));
		}
	};

	find_stmts_visitor v(filter, result);
	p->visit(v);
	return result;
}

template<typename T>
std::vector<find_stmts_result<T>> find_stmt(program_ptr p, std::function<bool(visitor &)> filter = [](visitor &){ return true; })
{
	auto results = find_stmts<T>(p, filter);
	if (results.empty())
		return results;

	std::sort(results.begin(), results.end());

	unsigned int index = std::geometric_distribution<unsigned int>(find_p)(re);
	if (index >= results.size())
		index = results.size() - 1;

	std::vector<find_stmts_result<T>> new_results;
	new_results.push_back(results[index]);
	return new_results;
}


#if 0
static void walk(program_ptr p, std::function<void(visitor &)> callback)
{
	struct walk_visitor: visitor {
		std::function<void(visitor &)> cb;

		walk_visitor(std::function<void(visitor &)> cb):
			cb(cb)
		{
		}

		void visit(expr_ptr &ref)
		{
			cb(*this);
		}
	};

	walk_visitor v(callback);
	p->visit(v);
}
#endif

// Integer transformations

static program_ptr transform_integer_to_statement_expression(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals
	auto int_literal_exprs = find_expr<int_literal_expression>(new_p);
	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	// Replace by a new expression
	std::vector<expr_ptr> stmts;
	auto new_e = std::make_shared<statement_expression>(generation,
		std::make_shared<block_statement>(generation, stmts),
		std::make_shared<expression_statement>(generation, int_e));
	*e.expr_ptr_ref = new_e;
	return new_p;
}

static program_ptr transform_integer_to_sum(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals
	auto int_literal_exprs = find_expr<int_literal_expression>(new_p);
	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	// Pick numbers that we know won't overflow (either here or in the generated program!)
	int min = std::numeric_limits<int>::min();
	int max = std::numeric_limits<int>::max();
	if (int_e->value < 0)
		max = int_e->value - min;
	else
		min = int_e->value - max;

	int value_a = std::uniform_int_distribution<int>(min, max)(re);
	int value_b = int_e->value - value_a;

	// Replace by a new expression
	auto a_expr = std::make_shared<int_literal_expression>(generation, value_a);
	auto b_expr = std::make_shared<int_literal_expression>(generation, value_b);
	auto new_e = std::make_shared<binop_expression>(generation, "+", a_expr, b_expr);
	*e.expr_ptr_ref = new_e;
	return new_p;
}

static int gcd(int a, int b)
{
	while (a != b) {
		if (a > b)
			a -= b;
		else
			b -= a;
	}

	return a;
}

static program_ptr transform_integer_to_product(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals
	auto int_literal_exprs = find_expr<int_literal_expression>(new_p);
	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	// TODO!
	int a = abs(int_e->value);
	if (a <= 1)
		return p;
	int b = std::uniform_int_distribution<int>(1, a - 1)(re);

	int value_a = gcd(a, b);
	int value_b = int_e->value / value_a;

	// Replace by a new expression
	auto a_expr = std::make_shared<int_literal_expression>(generation, value_a);
	auto b_expr = std::make_shared<int_literal_expression>(generation, value_b);
	auto new_e = std::make_shared<binop_expression>(generation, "*", a_expr, b_expr);
	*e.expr_ptr_ref = new_e;
	return new_p;
}

static program_ptr transform_integer_to_negation(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals
	auto int_literal_exprs = find_expr<int_literal_expression>(new_p);
	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	// Replace by a new expression
	auto arg_expr = std::make_shared<int_literal_expression>(generation, ~int_e->value);
	auto new_e = std::make_shared<preop_expression>(generation, "~", arg_expr);
	*e.expr_ptr_ref = new_e;
	return new_p;
}

static program_ptr transform_integer_to_conjunction(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals
	auto int_literal_exprs = find_expr<int_literal_expression>(new_p);
	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	int r = std::uniform_int_distribution<int>(std::numeric_limits<int>::min(), std::numeric_limits<int>::max())(re);

	// Pick numbers that we know won't overflow (either here or in the generated program!)
	int value_a = int_e->value | r;
	int value_b = int_e->value | ~r;

	// Replace by a new expression
	auto a_expr = std::make_shared<int_literal_expression>(generation, value_a);
	auto b_expr = std::make_shared<int_literal_expression>(generation, value_b);
	auto new_e = std::make_shared<binop_expression>(generation, "&", a_expr, b_expr);
	*e.expr_ptr_ref = new_e;
	return new_p;
}

static program_ptr transform_integer_to_disjunction(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals
	auto int_literal_exprs = find_expr<int_literal_expression>(new_p);
	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	int r = std::uniform_int_distribution<int>(std::numeric_limits<int>::min(), std::numeric_limits<int>::max())(re);

	// Pick numbers that we know won't overflow (either here or in the generated program!)
	int value_a = int_e->value & r;
	int value_b = int_e->value & ~r;

	// Replace by a new expression
	auto a_expr = std::make_shared<int_literal_expression>(generation, value_a);
	auto b_expr = std::make_shared<int_literal_expression>(generation, value_b);
	auto new_e = std::make_shared<binop_expression>(generation, "|", a_expr, b_expr);
	*e.expr_ptr_ref = new_e;
	return new_p;
}

static program_ptr transform_integer_to_xor(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals
	auto int_literal_exprs = find_expr<int_literal_expression>(new_p);
	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	int r = std::uniform_int_distribution<int>(std::numeric_limits<int>::min(), std::numeric_limits<int>::max())(re);

	// Pick numbers that we know won't overflow (either here or in the generated program!)
	int value_a = ~r;
	int value_b = r ^ ~int_e->value;

	// Replace by a new expression
	auto a_expr = std::make_shared<int_literal_expression>(generation, value_a);
	auto b_expr = std::make_shared<int_literal_expression>(generation, value_b);
	auto new_e = std::make_shared<binop_expression>(generation, "^", a_expr, b_expr);
	*e.expr_ptr_ref = new_e;
	return new_p;
}

static program_ptr transform_integer_1_to_equals(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals
	auto _int_literal_exprs = find_expr<int_literal_expression>(new_p);
	decltype(_int_literal_exprs) int_literal_exprs;
	for (auto x: _int_literal_exprs) {
		if (x.expr->value == 1)
			int_literal_exprs.push_back(x);
	}

	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	int r = std::uniform_int_distribution<int>(std::numeric_limits<int>::min(), std::numeric_limits<int>::max())(re);

	// Replace by a new expression
	auto a_expr = std::make_shared<int_literal_expression>(generation, r);
	auto b_expr = std::make_shared<int_literal_expression>(generation, r);
	auto new_e = std::make_shared<binop_expression>(generation, "==", a_expr, b_expr);
	*e.expr_ptr_ref = new_e;
	return new_p;
}

static program_ptr transform_integer_1_to_not_equals(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals
	auto _int_literal_exprs = find_expr<int_literal_expression>(new_p);
	decltype(_int_literal_exprs) int_literal_exprs;
	for (auto x: _int_literal_exprs) {
		if (x.expr->value == 1)
			int_literal_exprs.push_back(x);
	}

	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	// Pick two random numbers (not the same)
	int r1 = std::uniform_int_distribution<int>(std::numeric_limits<int>::min(), std::numeric_limits<int>::max())(re);
	int r2;
	do {
		r2 = std::uniform_int_distribution<int>(std::numeric_limits<int>::min(), std::numeric_limits<int>::max())(re);
	} while (r2 == r1);

	// Replace by a new expression
	auto a_expr = std::make_shared<int_literal_expression>(generation, r1);
	auto b_expr = std::make_shared<int_literal_expression>(generation, r2);
	auto new_e = std::make_shared<binop_expression>(generation, "!=", a_expr, b_expr);
	*e.expr_ptr_ref = new_e;
	return new_p;
}

static program_ptr transform_integer_to_variable(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals
	auto int_literal_exprs = find_expr<int_literal_expression>(new_p);
	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	// Replace by a new expression
	auto new_var = std::make_shared<variable_expression>(generation, new_p->ids.new_ident());
	auto new_decl = std::make_shared<declaration_statement>(generation, int_type, new_var, int_e);
	auto body = std::dynamic_pointer_cast<block_statement>(e.fn->body);
	body->statements.insert(body->statements.begin() + 0, new_decl);
	*e.expr_ptr_ref = new_var;
	return new_p;
}

// TODO: by creating global declarations we get a problem with later transformations
static program_ptr transform_integer_to_global_variable(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals (within a function)
	auto int_literal_exprs = find_expr<int_literal_expression>(new_p);
	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	// Replace by a new expression
	auto new_var = std::make_shared<variable_expression>(generation, new_p->ids.new_ident());
	auto new_decl = std::make_shared<declaration_statement>(generation, int_type, new_var, int_e);
	new_p->toplevel_decls.insert(new_p->toplevel_decls.begin() + 0, new_decl);
	*e.expr_ptr_ref = new_var;
	return new_p;
}

static program_ptr transform_integer_to_function(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals (within a function)
	auto int_literal_exprs = find_expr<int_literal_expression>(new_p);
	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	// Create new function
	auto new_body = std::make_shared<block_statement>(generation);
	new_body->statements.push_back(std::make_shared<return_statement>(generation, int_e));
	auto new_fn = std::make_shared<function>(new_p->ids.new_ident(), int_type, std::vector<type_ptr>(), new_body);
	new_p->toplevel_fns.insert(new_p->toplevel_fns.begin() + 0, new_fn);

	// Replace by a new expression
	auto new_call = std::make_shared<call_expression>(generation,
		std::make_shared<variable_expression>(generation, new_fn->name));
	*e.expr_ptr_ref = new_call;
	return new_p;
}

static program_ptr transform_integer_to_builtin_constant_p(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals
	auto int_literal_exprs = find_expr<int_literal_expression>(new_p);
	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	// Replace by a new expression
	std::vector<expr_ptr> args;
	args.push_back(std::make_shared<int_literal_expression>(generation, int_e->value));
	auto new_call = std::make_shared<call_expression>(generation,
		std::make_shared<variable_expression>(generation, "__builtin_constant_p"), args);
	auto a_expr = std::make_shared<int_literal_expression>(generation, int_e->value);
	auto b_expr = std::make_shared<int_literal_expression>(generation, int_e->value);
	auto new_ternop = std::make_shared<ternop_expression>(generation, "?", ":", new_call, a_expr, b_expr);
	*e.expr_ptr_ref = new_ternop;
	return new_p;
}

static program_ptr transform_insert_builtin_expect(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals
	auto int_literal_exprs = find_expr<int_literal_expression>(new_p);
	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	int value;
	if (std::uniform_int_distribution<int>(0, 3)(re) == 0)
		value = int_e->value;
	else
		value = std::uniform_int_distribution<int>(std::numeric_limits<int>::min(), std::numeric_limits<int>::max())(re);

	// Replace by a new expression
	std::vector<expr_ptr> args;
	args.push_back(std::make_shared<int_literal_expression>(generation, int_e->value));
	args.push_back(std::make_shared<int_literal_expression>(generation, value));
	auto new_call = std::make_shared<call_expression>(generation,
		std::make_shared<variable_expression>(generation, "__builtin_expect"), args);
	*e.expr_ptr_ref = new_call;
	return new_p;
}

static program_ptr transform_insert_builtin_prefetch(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all block statements
	auto block_stmts = find_stmt<block_statement>(new_p);
	if (block_stmts.empty())
		return p;

	// Pick a random one to mutate
	auto stmt = block_stmts[std::uniform_int_distribution<unsigned int>(0, block_stmts.size() - 1)(re)];
	auto block_stmt = stmt.stmt;

	int value = std::uniform_int_distribution<int>(std::numeric_limits<int>::min(), std::numeric_limits<int>::max())(re);

	// Replace by a new expression
	std::vector<expr_ptr> args;
	args.push_back(std::make_shared<cast_expression>(generation, voidp_type,
		std::make_shared<int_literal_expression>(generation, value)));
	auto new_stmt = std::make_shared<expression_statement>(generation,
		std::make_shared<call_expression>(generation,
			std::make_shared<variable_expression>(generation, "__builtin_prefetch"), args));
	auto &statements = block_stmt->statements;
	statements.insert(statements.begin() + std::uniform_int_distribution<unsigned int>(0, statements.size())(re), new_stmt);
	return new_p;
}

static program_ptr transform_insert_if(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all block statements
	auto block_stmts = find_stmt<block_statement>(new_p);
	if (block_stmts.empty())
		return p;

	// Pick a random one to mutate
	auto stmt = block_stmts[std::uniform_int_distribution<unsigned int>(0, block_stmts.size() - 1)(re)];
	auto block_stmt = stmt.stmt;

	auto cond_expr = std::make_shared<int_literal_expression>(generation, std::uniform_int_distribution<int>(0, 1)(re));
	expr_ptr true_stmt = std::make_shared<block_statement>(generation);
	expr_ptr false_stmt = std::make_shared<block_statement>(generation);

	if (cond_expr->value)
		false_stmt = std::make_shared<unreachable_statement>(generation, false_stmt);
	else
		true_stmt = std::make_shared<unreachable_statement>(generation, true_stmt);

	auto new_stmt = std::make_shared<if_statement>(generation, cond_expr, true_stmt, false_stmt);
	auto &statements = block_stmt->statements;
	statements.insert(statements.begin() + std::uniform_int_distribution<unsigned int>(0, statements.size())(re), new_stmt);
	return new_p;
}

static program_ptr transform_insert_asm(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all block statements
	auto block_stmts = find_stmt<block_statement>(new_p);
	if (block_stmts.empty())
		return p;

	// Pick a random one to mutate
	auto stmt = block_stmts[std::uniform_int_distribution<unsigned int>(0, block_stmts.size() - 1)(re)];
	auto block_stmt = stmt.stmt;

	auto new_stmt = std::make_shared<asm_statement>(generation, std::uniform_int_distribution<unsigned int>(0, 1)(re), std::vector<expr_ptr>(), std::vector<expr_ptr>());
	auto body = std::dynamic_pointer_cast<block_statement>(new_p->toplevel_fn->body);
	auto &statements = block_stmt->statements;
	statements.insert(statements.begin() + std::uniform_int_distribution<unsigned int>(0, statements.size())(re), new_stmt);
	return new_p;
}

#if 0
static program_ptr transform_insert_asm_2(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all block statements
	auto block_stmts = find_stmt<block_statement>(new_p);
	if (block_stmts.empty())
		return p;

	// Pick a random one to mutate
	auto stmt = block_stmts[std::uniform_int_distribution<unsigned int>(0, block_stmts.size() - 1)(re)];
	auto block_stmt = stmt.stmt;

	auto constraint_expr = std::make_shared<asm_constraint_expression>("+r", );
	auto new_stmt = std::make_shared<asm_statement>(std::uniform_int_distribution<unsigned int>(0, 1)(re), std::vector<expr_ptr>{constraint_expr}, std::vector<expr_ptr>());
	auto body = std::dynamic_pointer_cast<block_statement>(new_p->toplevel_fn->body);
	auto &statements = block_stmt->statements;
	statements.insert(statements.begin() + std::uniform_int_distribution<unsigned int>(0, statements.size())(re), new_stmt);
	return new_p;
}
#endif

static program_ptr transform_insert_builtin_unreachable(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all unreachable block statements
	auto block_stmts = find_stmt<block_statement>(new_p, [](visitor &v) { return v.is_unreachable(); });
	if (block_stmts.empty())
		return p;

	// Pick a random one to mutate
	auto stmt = block_stmts[std::uniform_int_distribution<unsigned int>(0, block_stmts.size() - 1)(re)];
	auto block_stmt = stmt.stmt;

	// Replace by a new expression
	auto new_stmt = std::make_shared<expression_statement>(generation,
		std::make_shared<call_expression>(generation,
			std::make_shared<variable_expression>(generation, "__builtin_unreachable"), std::vector<expr_ptr>()));
	auto &statements = block_stmt->statements;
	statements.insert(statements.begin() + std::uniform_int_distribution<unsigned int>(0, statements.size())(re), new_stmt);
	return new_p;
}

static program_ptr transform_insert_builtin_trap(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all unreachable block statements
	auto block_stmts = find_stmt<block_statement>(new_p, [](visitor &v) { return v.is_unreachable(); });
	if (block_stmts.empty())
		return p;

	// Pick a random one to mutate
	auto stmt = block_stmts[std::uniform_int_distribution<unsigned int>(0, block_stmts.size() - 1)(re)];
	auto block_stmt = stmt.stmt;

	// Replace by a new expression
	auto new_stmt = std::make_shared<expression_statement>(generation,
		std::make_shared<call_expression>(generation,
			std::make_shared<variable_expression>(generation, "__builtin_trap"), std::vector<expr_ptr>()));
	auto &statements = block_stmt->statements;
	statements.insert(statements.begin() + std::uniform_int_distribution<unsigned int>(0, statements.size())(re), new_stmt);
	return new_p;
}

static program_ptr transform_insert_div_by_0(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all unreachable block statements
	auto block_stmts = find_stmt<block_statement>(new_p, [](visitor &v) { return v.is_unreachable(); });
	if (block_stmts.empty())
		return p;

	// Pick a random one to mutate
	auto stmt = block_stmts[std::uniform_int_distribution<unsigned int>(0, block_stmts.size() - 1)(re)];
	auto block_stmt = stmt.stmt;

	// Replace by a new expression
	auto a_expr = std::make_shared<int_literal_expression>(generation, 1);
	auto b_expr = std::make_shared<int_literal_expression>(generation, 0);
	auto new_stmt = std::make_shared<expression_statement>(generation,
		std::make_shared<binop_expression>(generation, "/", a_expr, b_expr));
	auto &statements = block_stmt->statements;
	statements.insert(statements.begin() + std::uniform_int_distribution<unsigned int>(0, statements.size())(re), new_stmt);
	return new_p;
}

static program_ptr transform_integer_to_variable_and_asm(program_ptr p)
{
	program_ptr new_p = p->clone();
	unsigned int generation = new_p->generation;

	// First, find all integer literals
	auto int_literal_exprs = find_expr<int_literal_expression>(new_p);
	if (int_literal_exprs.empty())
		return p;

	// Pick a random one to mutate
	auto e = int_literal_exprs[std::uniform_int_distribution<unsigned int>(0, int_literal_exprs.size() - 1)(re)];
	auto int_e = e.expr;

	// Replace by a new expression
	auto new_var = std::make_shared<variable_expression>(generation, new_p->ids.new_ident());
	auto new_decl = std::make_shared<declaration_statement>(generation, int_type, new_var, int_e);
	auto body = std::dynamic_pointer_cast<block_statement>(e.fn->body);
	body->statements.insert(body->statements.begin() + 0, new_decl);

	auto constraint_expr = std::make_shared<asm_constraint_expression>(generation, "+r",
		std::make_shared<variable_expression>(generation, new_var->name));
	auto new_stmt = std::make_shared<asm_statement>(generation, std::uniform_int_distribution<unsigned int>(0, 1)(re), std::vector<expr_ptr>{constraint_expr}, std::vector<expr_ptr>());
	body->statements.insert(body->statements.begin() + 1, new_stmt);
	*e.expr_ptr_ref = new_var;
	return new_p;
}

// List of transformations

typedef program_ptr (*transformation)(program_ptr);

static const std::vector<transformation> transformations = {
	&transform_integer_to_statement_expression,
	&transform_integer_to_sum,
	&transform_integer_to_product,
	&transform_integer_to_negation,
	&transform_integer_to_conjunction,
	&transform_integer_to_disjunction,
	&transform_integer_to_xor,
	&transform_integer_1_to_equals,
	&transform_integer_1_to_not_equals,
	&transform_integer_to_variable,
	&transform_integer_to_global_variable,
	&transform_integer_to_function,
	&transform_integer_to_builtin_constant_p,
	&transform_insert_builtin_expect,
	&transform_insert_builtin_prefetch,
	&transform_insert_if,
	&transform_insert_asm,
	&transform_insert_builtin_unreachable,
	&transform_insert_builtin_trap,
	&transform_insert_div_by_0,
	&transform_integer_to_variable_and_asm,
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

	//atexit(remove_shm);

	char *shm_str;
	if (asprintf(&shm_str, "%d", shm_id) == -1)
		error(EXIT_FAILURE, errno, "asprintf()");
	setenv(SHM_ENV_VAR, shm_str, 1);
	free(shm_str);

	trace_bits = (uint8_t *) shmat(shm_id, NULL, 0);
	if (!trace_bits)
		error(EXIT_FAILURE, errno, "shmat()");
}

// Main

/*
 * One of the most difficult things to get right is how many transformations
 * to apply before attempting to recompile a program. The problem is that
 * large files take a long time to compile, but if we apply few transformations
 * then we're most likely wasting time because we won't find any new coverage.
 *
 * What we should do is:
 *  - first try to collect coverage for some ~1000 small files with ~50 transformations each (~32 lines of code)
 *  - then try to extend the small test-cases one by one by applying a smaller number of transformations (?)
 */

static unsigned int trace_bits_counters[MAP_SIZE] = {};
static unsigned int nr_bits;

static bool build_and_run(program_ptr p)
{
	FILE *fcurr = fopen("/tmp/current.cc", "w+");
	if (!fcurr)
		error(EXIT_FAILURE, errno, "fopen()");
	p->print(fcurr);
	fclose(fcurr);

	int stdin_pipefd[2];
	if (pipe2(stdin_pipefd, 0) == -1)
		error(EXIT_FAILURE, errno, "pipe2()");

	int stderr_pipefd[2];
	if (pipe2(stderr_pipefd, 0) == -1)
		error(EXIT_FAILURE, errno, "pipe2()");

	setup_shm();

	pid_t child = fork();
	if (child == -1)
		error(EXIT_FAILURE, errno, "fork()");

	if (child == 0) {
		close(stdin_pipefd[1]);
		dup2(stdin_pipefd[0], STDIN_FILENO);
		close(stdin_pipefd[0]);

		close(stderr_pipefd[0]);
		dup2(stderr_pipefd[1], STDERR_FILENO);
		close(stderr_pipefd[1]);
		if (execlp("/home/vegard/personal/programming/gcc/build/gcc/cc1plus", "cc1plus", "-quiet", "-g", "-O3", "-Wno-div-by-zero", "-Wno-unused-value", "-Wno-int-to-pointer-cast", "-std=c++14", "-fpermissive", "-fwhole-program", "-ftree-pre", "-fstack-protector-all", "-faggressive-loop-optimizations", "-fauto-inc-dec", "-fbranch-probabilities", "-fbranch-target-load-optimize2", "-fcheck-data-deps", "-fcompare-elim", "-fdce", "-fdse", "-fexpensive-optimizations", "-fhoist-adjacent-loads", "-fgcse-lm", "-fgcse-sm", "-fipa-profile", "-fno-toplevel-reorder", "-fsched-group-heuristic", "-fschedule-fusion", "-fschedule-insns", "-fschedule-insns2", "-ftracer", "-funroll-loops", "-fvect-cost-model", "-o", "prog.s", NULL) == -1)
		//if (execlp("/home/vegard/personal/programming/gcc/build/gcc/cc1plus", "cc1plus", "-quiet", "-g", "-Wall", "-std=c++14", "-ftree-pre", "-fstack-protector-all", "-faggressive-loop-optimizations", "-fauto-inc-dec", "-fbranch-probabilities", "-fbranch-target-load-optimize2", "-fcheck-data-deps", "-fcompare-elim", "-fdce", "-fdse", "-fexpensive-optimizations", "-fhoist-adjacent-loads", "-fgcse-lm", "-fgcse-sm", "-fipa-profile", "-fno-toplevel-reorder", "-fsched-group-heuristic", "-fschedule-fusion", "-fschedule-insns", "-fschedule-insns2", "-ftracer", "-funroll-loops", "-fvect-cost-model", "-o", "prog.s", NULL) == -1)
			error(EXIT_FAILURE, errno, "execvp()");
	}

	close(stdin_pipefd[0]);
	FILE *f = fdopen(stdin_pipefd[1], "w");
	if (!f)
		error(EXIT_FAILURE, errno, "fdopen()");
	p->print(f);
	fclose(f);

	static char stderr_buffer[10 * 4096];
	size_t stderr_len;

	{
		close(stderr_pipefd[1]);
		FILE *f = fdopen(stderr_pipefd[0], "r");
		if (!f)
			error(EXIT_FAILURE, errno, "fdopen()");

		stderr_len = fread(stderr_buffer, 1, sizeof(stderr_buffer), f);
		if (stderr_len > 0)
			stderr_buffer[stderr_len - 1] = '\0';

		fclose(f);
	}

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

	if (WIFSIGNALED(status)) {
		printf("cc1plus WIFSIGNALED()\n");
		exit(1);
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
		printf("cc1plus WIFEXITED; exit code = %d\n", WEXITSTATUS(status));

		// TODO
		bool ignore = false;
		if (strstr(stderr_buffer, "internal compiler error")) {
			if (strstr(stderr_buffer, "unexpected expression") && strstr(stderr_buffer, "of kind asm_expr"))
				ignore = true;
			if (strstr(stderr_buffer, "gimplification failed"))
				ignore = true;
		}

		if (ignore) {
			remove_shm();
			return false;
		}

		exit(1);
	}

	// TODO
	if (system("g++ prog.s") != 0)
		error(EXIT_FAILURE, 0, "system()");

	{
		int pipefd[2];
		if (pipe2(pipefd, 0) == -1)
			error(EXIT_FAILURE, errno, "pipe2()");

		pid_t child = fork();
		if (child == -1)
			error(EXIT_FAILURE, errno, "fork()");

		if (child == 0) {
			close(pipefd[0]);
			dup2(pipefd[1], STDOUT_FILENO);
			close(pipefd[1]);

			if (execl("./a.out", "./a.out", NULL) == -1)
				error(EXIT_FAILURE, errno, "execl()");
		}

		int actual_result = 0;

		close(pipefd[1]);
		FILE *f = fdopen(pipefd[0], "r");
		if (!f)
			error(EXIT_FAILURE, errno, "fdopen()");
		if (fscanf(f, "%d", &actual_result) != 1)
			error(EXIT_FAILURE, 0, "fscanf()");
		fclose(f);

		if (actual_result != p->toplevel_value) {
			printf("prog unexpected result: %d vs. %d\n", actual_result, p->toplevel_value);
			exit(1);
		}

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

		if (WIFSIGNALED(status)) {
			printf("prog WIFSIGNALED\n");
			exit(1);
		}

		if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
			printf("prog WIFEXITED; exit code = %d\n", WEXITSTATUS(status));
			exit(1);
		}
	}

	unsigned int nr_new_bits = 0;
	for (unsigned int i = 0; i < MAP_SIZE; ++i) {
		if (trace_bits[i] && ++trace_bits_counters[i] == 1)
			++nr_new_bits;
	}

	nr_bits += nr_new_bits;

	printf("%u bits; %u new\n", nr_bits, nr_new_bits);

	remove_shm();

	return nr_new_bits > 0;
}

struct testcase {
	program_ptr program;
	unsigned int nr_failures;
	double nr_transformations;

	testcase(program_ptr p):
		program(p),
		nr_failures(0),
		nr_transformations(10)
	{
	}
};

int main(int argc, char *argv[])
{
	re = std::default_random_engine(r());

	// Seed the set of programs with some randomly generated ones
	std::vector<testcase> testcases;

	const float alpha = 0.85;

	while (1) {
		while (testcases.size() < 250) {
			printf("[%3lu new]... ", testcases.size());

			auto p = std::make_shared<program>(std::uniform_int_distribution<int>(std::numeric_limits<int>::min(), std::numeric_limits<int>::max())(re));
			for (unsigned int i = 0; i < 50; ++i) {
				unsigned int transformation_i = std::uniform_int_distribution<unsigned int>(0, transformations.size() - 1)(re);
				p = transformations[transformation_i](p);
			}

			if (build_and_run(p))
				testcases.push_back(testcase(p));
		}

		unsigned int testcase_i = std::uniform_int_distribution<unsigned int>(0, testcases.size() - 1)(re);
		auto &t = testcases[testcase_i];

		printf("[%3u | %2u | %5.2f]... ", testcase_i, t.nr_failures, t.nr_transformations);

		auto p = t.program;
		for (unsigned int i = 0; i < (unsigned int) std::max(1, (int) ceil(t.nr_transformations)); ++i) {
			unsigned int transformation_i = std::uniform_int_distribution<unsigned int>(0, transformations.size() - 1)(re);
			p = transformations[transformation_i](p);
		}

		if (build_and_run(p)) {
			t.nr_transformations = alpha * t.nr_transformations + (1 - alpha) * (10 * t.nr_failures);
			t.nr_failures = 0;
			t.program = p;
		} else {
			if (++t.nr_failures == 50)
				testcases.erase(testcases.begin() + testcase_i);
			else
				t.nr_transformations = alpha * t.nr_transformations + (1 - alpha) * (10 * t.nr_failures);
		}
	}

	return 0;
}
