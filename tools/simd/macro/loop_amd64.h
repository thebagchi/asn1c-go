// Loop brackets, and a demonstration of the two limits the plan is shaped
// around.
//
// The assembler's preprocessor has no token pasting, so a macro cannot invent a
// label and both label names are passed in. Its arguments also split on commas
// with no way to quote one, so a loop body cannot be an argument and is written
// between the two macros rather than passed to one.

// LOOP_BEGIN opens a counted loop, leaving it when ctr reaches limit.
#define LOOP_BEGIN(top, done, ctr, limit) \
top: \
	CMPQ ctr, limit \
	JGE  done

// LOOP_END closes the loop LOOP_BEGIN opened, advancing ctr by step.
#define LOOP_END(top, done, ctr, step) \
	ADDQ step, ctr \
	JMP  top \
done:
