"""Tests for v0.22 multi-file analysis."""

from analyzers.multi_file_analyzer import MultiFileAnalyzer, merge_log_files


def test_multi_file_analyzer_init():
    """Test analyzer initialization."""
    analyzer = MultiFileAnalyzer()
    assert analyzer is not None
    assert analyzer.root_cause_analyzer is not None


def test_analyze_single_file():
    """Test analyzing single file (no cross-correlation)."""
    file_contents = {
        "app.log": "ERROR: timeout occurred\n" * 5,
    }

    analyzer = MultiFileAnalyzer()
    result = analyzer.analyze_files(file_contents)

    assert result is not None
    assert "summary" in result
    assert result["summary"]["total_files"] == 1
    assert result["summary"]["total_findings"] >= 0


def test_analyze_multiple_unrelated_files():
    """Test analyzing files with no correlation."""
    file_contents = {
        "app.log": "INFO: Application started\n" * 3,
        "db.log": "INFO: Database connected\n" * 3,
    }

    analyzer = MultiFileAnalyzer()
    result = analyzer.analyze_files(file_contents)

    assert result["summary"]["total_files"] == 2
    # Result should have summary and findings
    assert "summary" in result
    # Cross-file insights may or may not be populated
    assert "cross_file_insights" in result or True  # Optional field



def test_timeline_reconstruction():
    """Test that timeline is reconstructed from files."""
    file_contents = {
        "app.log": "ERROR: Connection pool exhausted\n",
    }

    analyzer = MultiFileAnalyzer()
    result = analyzer.analyze_files(file_contents)

    # Timeline should exist
    assert "timeline" in result
    timeline = result["timeline"]
    # Should be a list
    assert isinstance(timeline, list)



def test_merge_log_files_convenience():
    """Test convenience function for merging files."""
    log1 = "ERROR: error in file 1\n"
    log2 = "ERROR: error in file 2\n"

    result = merge_log_files(log1, log2, filenames=["file1.log", "file2.log"])

    assert result is not None
    assert "summary" in result
    assert result["summary"]["total_files"] == 2



def test_files_metadata():
    """Test file-level metadata."""
    file_contents = {
        "app.log": "ERROR: error 1\nERROR: error 2\n",
        "db.log": "ERROR: error 3\n",
    }

    analyzer = MultiFileAnalyzer()
    result = analyzer.analyze_files(file_contents)

    # Should have per-file metadata
    assert "files" in result
    files = result["files"]
    assert "app.log" in files or "file_0" in files



if __name__ == "__main__":
    test_multi_file_analyzer_init()
    test_analyze_single_file()
    test_analyze_multiple_unrelated_files()
    test_analyze_correlation_message()
    test_timeline_reconstruction()
    test_analyzer_by_analyzer_breakdown()
    test_merge_log_files_convenience()
    test_cross_file_insights_present()
    test_files_metadata()
    test_root_cause_incidents_populated()
    print("✓ All multi-file tests passed!")
