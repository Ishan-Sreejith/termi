from termi import fallback_generator, ModelSuggestion


def check(instr: str, expected_cmd: str | None = None):
    result = fallback_generator(instr)
    assert isinstance(result, ModelSuggestion)
    assert result.command
    assert result.risk_level in {"low", "medium", "high", "critical"}
    if expected_cmd is not None:
        assert result.command.startswith(expected_cmd), (
            f"for {instr!r}: expected prefix {expected_cmd!r}, got {result.command!r}"
        )


class TestPwd:
    def test_pwd(self):
        check("current directory", "pwd")
        check("where am i", "pwd")
        check("print working directory", "pwd")

class TestDisk:
    def test_disk(self):
        check("disk space", "df -h")
        check("show disk usage", "df -h")
        check("storage size", "df -h")
        check("disk usage of /home", "du -sh /home")

class TestDate:
    def test_date(self):
        check("what time is it", "date")
        check("current date", "date")
        check("show clock", "date")

class TestProcesses:
    def test_ps(self):
        check("running processes", "ps")
        check("all running processes", "ps aux")

class TestNetwork:
    def test_ip(self):
        check("show ip address", "ifconfig")
        check("what is my ip", "ifconfig")

    def test_ping(self):
        check("ping google.com", "ping -c 4 google.com")
        check("ping to google.com", "ping -c 4 google.com")
        check("ping to 8.8.8.8", "ping -c 4 8.8.8.8")
        check("check network connectivity", "ping -c 4 8.8.8.8")

class TestCreate:
    def test_mkdir(self):
        check("create directory foo", "mkdir -p foo")
        check("make folder bar", "mkdir -p bar")
        check("create a directory called mydir", "mkdir -p mydir")

    def test_touch(self):
        check("create file hello.txt", "touch hello.txt")
        check("make a file named test.py", "touch test.py")
        check("new file data.csv", "touch data.csv")

class TestDelete:
    def test_delete_all_ext(self):
        check("delete all txt files", "rm -v *.txt")
        check("delete all .pdf files", "rm -v *.pdf")
        check("remove all json files", "rm -v *.json")

    def test_delete_named(self):
        check("delete temp.txt", "rm temp.txt")
        check("remove data.csv", "rm data.csv")

    def test_delete_folder(self):
        check("delete the folder mydata", "rm -r mydata")
        check("remove directory oldstuff", "rm -r oldstuff")

class TestCopy:
    def test_copy(self):
        check("copy file.txt to backup.txt", "cp file.txt backup.txt")
        check("cp src.txt into dst.txt", "cp src.txt dst.txt")

class TestMove:
    def test_move(self):
        check("move file.txt to /tmp", "mv file.txt /tmp")
        check("mv old.txt to new.txt", "mv old.txt new.txt")

class TestCat:
    def test_cat(self):
        check("show contents of notes.txt", "cat notes.txt")
        check("display readme.md", "cat readme.md")
        check("cat config.json", "cat config.json")
        check("view log.txt", "cat log.txt")
        check("print contents of file.txt", "cat file.txt")

class TestLs:
    def test_ls(self):
        check("list files", "ls")
        check("list all files", "ls -la")
        check("show hidden files", "ls -la")
        check("long list", "ls -l")
        check("show detailed listing", "ls -l")

class TestGrep:
    def test_grep(self):
        check("search for foo in bar.txt", "grep -n foo bar.txt")
        check("grep for 'error' in log.txt", "grep -n error log.txt")

    def test_grep_preserves_case(self):
        result = fallback_generator("search for ErrorMessage in app.log")
        assert "ErrorMessage" in result.command
        assert "errormessage" not in result.command

class TestFind:
    def test_find(self):
        check("find files named config.json", "find . -name config.json")
        check("find named '*.py'", "find . -name '*.py'")

class TestFallback:
    def test_unknown(self):
        result = fallback_generator("do something completely random")
        assert "fallback" in result.command
