// (c) Peter Kankowski, 2007. http://smallcode.weblogs.us mailto:kankowski@narod.ru
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// ================================
//   Simple expression evaluator
// ================================
// Error codes
enum EXPR_EVAL_ERR {
	EEE_NO_ERROR = 0,
	EEE_PARENTHESIS = 1,
	EEE_WRONG_CHAR = 2,
	EEE_DIVIDE_BY_ZERO = 3
};
typedef char EVAL_CHAR;
class ExprEval {
private:
	EXPR_EVAL_ERR _err;
	EVAL_CHAR* _err_pos;
	int _paren_count;
	// Parse a number or an expression in parenthesis
	double ParseAtom(EVAL_CHAR*& expr) {
		// Skip spaces
		while(*expr == ' ')
			expr++;
		// Handle the sign before parenthesis (or before number)
		bool negative = false;
		if(*expr == '-') {
			negative = true;
			expr++;
		}
		if(*expr == '+') {
			expr++;
		}
		// Check if there is parenthesis
		if(*expr == '(') {
			expr++;
			_paren_count++;
			double res = ParseSummands(expr);
			if(*expr != ')') {
				// Unmatched opening parenthesis
				_err = EEE_PARENTHESIS;
				_err_pos = expr;
				return 0;
			}
			expr++;
			_paren_count--;
			return negative ? -res : res;
		}
		// It should be a number; convert it to double
		char* end_ptr = expr;
    while ((*end_ptr == '1') || (*end_ptr == '0')) {
      end_ptr ++;
    }
    // double res = strtod(expr, &end_ptr);
		if(end_ptr == expr) {
			// Report error
			_err = EEE_WRONG_CHAR;
			_err_pos = expr;
			return 0;
		}
    double res = strtod(expr, 0);
		// Advance the pointer and return the result
		expr = end_ptr;
		return negative ? -res : res;
	}
	// Parse multiplication and division
	double ParseFactors(EVAL_CHAR*& expr) {
		double num1 = ParseAtom(expr);
		for(;;) {
			// Skip spaces
			while(*expr == ' ')
				expr++;
			// Save the operation and position
			EVAL_CHAR op = *expr;
			EVAL_CHAR* pos = expr;
			if(op != '/' && op != '*')
				return num1;
			expr++;
			double num2 = ParseAtom(expr);
			// Perform the saved operation
			if(op == '/') {
				// Handle division by zero
				if(num2 == 0) {
					_err = EEE_DIVIDE_BY_ZERO;
					_err_pos = pos;
					return 0;
				}
				num1 /= num2;
			}
			else
				num1 *= num2;
		}
	}
	// Parse addition and subtraction
	double ParseSummands(EVAL_CHAR*& expr) {
		double num1 = ParseFactors(expr);
		for(;;) {
			// Skip spaces
			while(*expr == ' ')
				expr++;
			EVAL_CHAR op = *expr;
			if(op != '-' && op != '+')
				return num1;
			expr++;
			double num2 = ParseFactors(expr);
			if(op == '-')
				num1 -= num2;
			else
				num1 += num2;
		}
	}
public:
	double Eval(EVAL_CHAR* expr) {
		_paren_count = 0;
		_err = EEE_NO_ERROR;
		double res = ParseSummands(expr);
		// Now, expr should point to '\0', and _paren_count should be zero
		if(_paren_count != 0 || *expr == ')') {
			_err = EEE_PARENTHESIS;
			_err_pos = expr;
			return 0;
		}
		if(*expr != '\0') {
			_err = EEE_WRONG_CHAR;
			_err_pos = expr;
			return 0;
		}
		return res;
	};
	EXPR_EVAL_ERR GetErr() {
		return _err;
	}
	EVAL_CHAR* GetErrPos() {
		return _err_pos;
	}
};

extern "C" void success(float res) {
  printf("done\n");
  //printf("<%2.6f>", res);
}

int main(int argc, char* argv[]) {
	static const char *errors[] = {
		"no error",
		"parentheses don't match",
		"invalid character",
		"division by zero"};
    assert(argc > 1);
		char *expr = argv[1];
		if(*expr == '\0') return 0;
    printf("<%s>", expr);
		ExprEval eval;
		double res = eval.Eval(expr);
		assert(eval.GetErr() == EEE_NO_ERROR);
    success(res);
}
