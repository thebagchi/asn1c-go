package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thebagchi/asn1c-go/.tools/common"
)

const (
	LEVEL_ERROR = "error"
	LEVEL_LOG   = "log"
	REVISION    = "revision.md"
	ROW_CELLS   = 4
	FIX_ROW     = "add a row with When as YYYY-MM-DD HH:MM, Commit, Files, and Intent"
	FIX_FILE    = "name the file, or a parent directory, in the Files cell"
	CLOCK       = "2006-01-02 15:04"
)

// _Row is one data row of revision.md.
type _Row struct {
	when   string
	commit string
	files  string
	intent string
}

// _Problems returns one line for each failure.
// A nil slice means the work tree has no open change.
// An empty slice means the new rows cover the changed Go files.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Problems(dir string) ([]string, error) {
	dirty, err := _Dirty(
		dir,
	)
	if err != nil {
		return nil, err
	}

	if !dirty {
		return nil, nil
	}

	rows, problems, err := _NewRows(
		dir,
	)
	if err != nil {
		return nil, err
	}

	if len(
		rows,
	) == 0 && len(
		problems,
	) == 0 {
		return []string{_Absent()}, nil
	}

	files, err := common.ChangedGo(
		dir,
	)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if _Covers(
			file,
			rows,
		) {
			continue
		}

		problems = append(
			problems,
			_Omit(
				file,
			),
		)
	}

	return problems, nil
}

// _Dirty reports whether the work tree differs from HEAD.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Dirty(dir string) (bool, error) {
	names, err := common.Git(
		dir,
		"diff",
		"--name-only",
		"HEAD",
	)
	if err != nil {
		return false, err
	}

	if strings.TrimSpace(
		names,
	) != "" {
		return true, nil
	}

	extra, err := common.Git(
		dir,
		"ls-files",
		"--others",
		"--exclude-standard",
	)
	if err != nil {
		return false, err
	}

	return strings.TrimSpace(
		extra,
	) != "", nil
}

// _NewRows reads the data rows that this change adds.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _NewRows(dir string) ([]*_Row, []string, error) {
	lines, err := _Added(
		dir,
	)
	if err != nil {
		return nil, nil, err
	}

	var (
		rows     []*_Row
		problems []string
	)

	for _, line := range lines {
		row, problem := _Parse(
			line,
		)
		if problem != "" {
			problems = append(
				problems,
				problem,
			)

			continue
		}

		if row == nil {
			continue
		}

		rows = append(
			rows,
			row,
		)
	}

	return rows, problems, nil
}

// _Added returns the lines this change adds to revision.md.
// An untracked file contributes every line. A missing file contributes none.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Added(dir string) ([]string, error) {
	untracked, err := _Untracked(
		dir,
	)
	if err != nil {
		return nil, err
	}

	if untracked {
		return _Read(
			dir,
		)
	}

	text, err := common.Git(
		dir,
		"diff",
		"--unified=0",
		"HEAD",
		"--",
		REVISION,
	)
	if err != nil {
		return nil, err
	}

	return _Plus(
		text,
	), nil
}

// _Plus returns the added lines of a unified diff.
// A file header that starts with +++ stays out.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Plus(text string) []string {
	var lines []string

	for _, line := range strings.Split(
		text,
		"\n",
	) {
		if !strings.HasPrefix(
			line,
			"+",
		) || strings.HasPrefix(
			line,
			"+++",
		) {
			continue
		}

		lines = append(
			lines,
			strings.TrimPrefix(
				line,
				"+",
			),
		)
	}

	return lines
}

// _Untracked reports whether revision.md is a new file.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Untracked(dir string) (bool, error) {
	text, err := common.Git(
		dir,
		"status",
		"--porcelain",
		"--",
		REVISION,
	)
	if err != nil {
		return false, err
	}

	for _, line := range strings.Split(
		text,
		"\n",
	) {
		if strings.HasPrefix(
			strings.TrimSpace(
				line,
			),
			"??",
		) {
			return true, nil
		}
	}

	return false, nil
}

// _Read returns every line of revision.md.
// A missing file returns no lines.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Read(dir string) ([]string, error) {
	data, err := os.ReadFile(
		filepath.Join(
			dir,
			REVISION,
		),
	)
	if err != nil {
		if os.IsNotExist(
			err,
		) {
			return nil, nil
		}

		return nil, err
	}

	return strings.Split(
		string(data),
		"\n",
	), nil
}

// _Parse reads one data row.
// A line that is not a data row returns a nil row and an empty problem.
// A data row with the wrong number of cells returns a problem.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Parse(line string) (*_Row, string) {
	cells := _Cells(
		line,
	)
	if len(
		cells,
	) == 0 || !_Clock(
		cells[0],
	) {
		return nil, ""
	}

	if len(
		cells,
	) != ROW_CELLS {
		return nil, _Fail(
			"a new row does not have When, Commit, Files, and Intent",
			FIX_ROW,
		)
	}

	var (
		row = &_Row{
			when:   cells[0],
			commit: cells[1],
			files:  cells[2],
			intent: cells[3],
		}
		gap = _Gap(
			row,
		)
	)
	if gap == "" {
		return row, ""
	}

	return nil, _Fail(
		"a new row has an empty "+gap+" cell",
		FIX_ROW,
	)
}

// _Cells returns the trimmed cells of one table line.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Cells(line string) []string {
	line = strings.Trim(
		strings.TrimSpace(
			line,
		),
		"|",
	)
	if strings.TrimSpace(
		line,
	) == "" {
		return nil
	}

	parts := strings.Split(
		line,
		"|",
	)

	var cells []string
	for _, part := range parts {
		cells = append(
			cells,
			strings.TrimSpace(
				part,
			),
		)
	}

	return cells
}

// _Clock reports whether text is a local time to the minute.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Clock(text string) bool {
	_, err := time.Parse(
		CLOCK,
		text,
	)

	return err == nil
}

// _Gap returns the name of the first empty cell after When.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Gap(row *_Row) string {
	switch {
	case row.commit == "":
		return "Commit"
	case row.files == "":
		return "Files"
	case row.intent == "":
		return "Intent"
	default:
		return ""
	}
}

// _Covers reports whether one changed file appears in any new row.
// A Files cell names the file or a parent directory.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Covers(
	file string,
	rows []*_Row,
) bool {
	for _, row := range rows {
		if _Hit(
			file,
			row.files,
		) {
			return true
		}
	}

	return false
}

// _Hit reports whether file matches one token of the Files cell.
// A comma inside parentheses is part of the note, not a separator.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Hit(
	file string,
	cell string,
) bool {
	for _, token := range _Tokens(
		cell,
	) {
		if file == token || strings.HasPrefix(
			file,
			token+"/",
		) {
			return true
		}
	}

	return false
}

// _Tokens splits a Files cell on commas that sit outside parentheses.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Tokens(cell string) []string {
	var (
		tokens []string
		depth  = 0
		start  = 0
	)

	for i := 0; i < len(
		cell,
	); i++ {
		switch cell[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth != 0 {
				continue
			}

			tokens = append(
				tokens,
				_Token(
					cell[start:i],
				),
			)
			start = i + 1
		}
	}

	return append(
		tokens,
		_Token(
			cell[start:],
		),
	)
}

// _Token returns the path at the start of one Files piece.
// The note after " (" is not part of the path.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Token(piece string) string {
	piece = strings.TrimSpace(
		piece,
	)

	path, _, ok := strings.Cut(
		piece,
		" (",
	)
	if ok {
		return strings.TrimSpace(
			path,
		)
	}

	return piece
}

// _Absent builds the error for a change with no new row.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Absent() string {
	return _Fail(
		"revision.md has no new row",
		FIX_ROW,
	)
}

// _Omit builds the error for one changed Go file the Files cell skips.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Omit(file string) string {
	return _Fail(
		"revision.md omits "+file,
		FIX_FILE,
	)
}

// _Fail builds one error line.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Fail(
	message string,
	fix string,
) string {
	return _Line(
		LEVEL_ERROR,
		message,
		fix,
	)
}

// _Line builds one line an agent can read.
// An empty fix omits the fix clause.
//
// Revisions:
//   - 2026-10-21 20:58: initial creation
func _Line(
	level string,
	message string,
	fix string,
) string {
	text := level + ": revision: " + message
	if fix == "" {
		return text
	}

	return text + ". fix: " + fix
}
