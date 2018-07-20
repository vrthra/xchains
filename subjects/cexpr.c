#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// ================================
//   Simple expression evaluator
// ================================
// Error codes
typedef enum  {
    EEE_NO_ERROR = 0,
    EEE_PARENTHESIS = 1,
    EEE_WRONG_CHAR = 2,
    EEE_DIVIDE_BY_ZERO = 3
} EXPR_EVAL_ERR;


int myAtoi(char *str) {
    int res = 0; // Initialize result
    for (int i = 0; str[i] != '\0'; ++i)
        res = res*10 + str[i] - '0';
    return res;
}

typedef char EVAL_CHAR;
typedef struct {
    EXPR_EVAL_ERR _err;
    EVAL_CHAR* _err_pos;
    int _paren_count;
} ExprEval;
double ParseAtom(ExprEval* self, EVAL_CHAR** expr);
double ParseFactors(ExprEval* self, EVAL_CHAR** expr);
// Parse a number or an expression in parenthesis
// Parse multiplication and division
double ParseFactors(ExprEval* self, EVAL_CHAR** expr) {
    double num1 = ParseAtom(self, expr);
    assert(self->_err == EEE_NO_ERROR);
    for(;;) {
        // Save the operation and position
        EVAL_CHAR op = **expr;
        EVAL_CHAR* pos = *expr;
        if(op != '/' && op != '*')
            return num1;
        (*expr)++;
        double num2 = ParseAtom(self, expr);
        assert(self->_err == EEE_NO_ERROR);
        // Perform the saved operation
        if(op == '/') {
            // Handle division by zero
            if(num2 == 0) {
                self->_err = EEE_DIVIDE_BY_ZERO;
                self->_err_pos = pos;
                return 0;
            }
            num1 /= num2;
        }
        else
            num1 *= num2;
    }
}
// Parse addition and subtraction
double ParseSummands(ExprEval* self, EVAL_CHAR** expr) {
    double num1 = ParseFactors(self, expr);
      assert(self->_err == EEE_NO_ERROR);
    for(;;) {
        EVAL_CHAR op = **expr;
        if(op != '-' && op != '+')
            return num1;
        (*expr)++;
        double num2 = ParseFactors(self, expr);
        assert(self->_err == EEE_NO_ERROR);
        if(op == '-')
            num1 -= num2;
        else
            num1 += num2;
    }
}
double Eval(ExprEval* self, EVAL_CHAR** expr) {
    self->_paren_count = 0;
    self->_err = EEE_NO_ERROR;
    double res = ParseSummands(self, expr);
    // Now, expr should point to '\0', and _paren_count should be zero
    if(self->_paren_count != 0 || **expr == ')') {
        self->_err = EEE_PARENTHESIS;
        self->_err_pos = *expr;
        return 0;
    }
    if(**expr != '\0') {
        self->_err = EEE_WRONG_CHAR;
        self->_err_pos = *expr;
        return 0;
    }
    return res;
};
EXPR_EVAL_ERR GetErr(ExprEval* self) {
    return self->_err;
}
EVAL_CHAR* GetErrPos(ExprEval* self) {
    return self->_err_pos;
}




double ParseAtom(ExprEval* self, EVAL_CHAR** expr) {
    // Handle the sign before parenthesis (or before number)
    int negative = 0;
    if(**expr == '-') {
        negative = 1;
        (*expr)++;
    }
    if(**expr == '+') {
        (*expr)++;
    }
    // Check if there is parenthesis
    if(**expr == '(') {
        (*expr)++;
        self->_paren_count++;
        double res = ParseSummands(self, expr);
        assert(self->_err == EEE_NO_ERROR);
        if(**expr != ')') {
            // Unmatched opening parenthesis
            self->_err = EEE_PARENTHESIS;
            self->_err_pos = *expr;
            return 0;
        }
        (*expr)++;
        self->_paren_count--;
        return negative ? -res : res;
    }
    // It should be a number; convert it to double
    char* end_ptr = *expr;
    /*while (
     (*end_ptr == '0')
     || (*end_ptr == '1')
     || (*end_ptr == '2')
     || (*end_ptr == '3')
     || (*end_ptr == '4')
     || (*end_ptr == '5')
     || (*end_ptr == '6')
     || (*end_ptr == '7')
     || (*end_ptr == '8')
     || (*end_ptr == '9')
     ) {
     end_ptr ++;
     }*/
    while ((*end_ptr >= '0') && (*end_ptr <= '9')) {
        end_ptr ++;
    }
    // double res = strtod(expr, &end_ptr);
    if(end_ptr == *expr) {
        // Report error
        self->_err = EEE_WRONG_CHAR;
        self->_err_pos = *expr;
        return 0;
    }
    //double res = strtol(expr, &end_ptr, 10);
    double res = atoi(*expr);
    // Advance the pointer and return the result
    *expr = end_ptr;
    return negative ? -res : res;
}

void my_success(float res) {
    printf("done\n");
    exit(0);
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
    ExprEval eval;
    double res = Eval(&eval, &expr);
    //printf("<%s>", expr);
    if(GetErr(&eval) == EEE_NO_ERROR) {
        my_success(res);
        return 0;
    } else {
        return 1;
        printf("error\n");
    }
}
