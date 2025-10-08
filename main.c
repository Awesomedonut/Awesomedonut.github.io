#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pwd.h>
#include <signal.h>
#include <sys/types.h>
#include <wait.h>

// copy pasted from header file
#define TMA_MSG "too many arguments"
#define HELP_HELP_MSG "show help information"
#define EXTERN_HELP_MSG "external command or application"
#define EXIT_HELP_MSG "exit the shell"
#define PWD_HELP_MSG "print the current directory"
#define CD_HELP_MSG "change the current directory"
#define HISTORY_HELP_MSG "print the history of commands"
#define HISTORY_INVALID_MSG "command invalid"
#define HISTORY_NO_LAST_MSG "no command entered"
#define GETCWD_ERROR_MSG "unable to get current directory"
#define CHDIR_ERROR_MSG "unable to change directory"
#define READ_ERROR_MSG "unable to read command"
#define FORK_ERROR_MSG "unable to fork"
#define EXEC_ERROR_MSG "unable to execute command"
#define WAIT_ERROR_MSG "unable to wait for child"

// TODO task0: shell prompt basic command support DONE
// write prompt which shwos curr working dir DOEN
// reads users input dONE
// tokenize said input done
// check if its background if theres and sig n DONE
// fork child
// wait and clean background DONE
// write errors if any accordign to reqs

#define BUF_SIZE 1000
#define TOK_SIZE 100

char *prev_dir = NULL;
volatile sig_atomic_t sigint_flag = 0;

void sigint_handler(int sigint) {
  write(STDOUT_FILENO, "\n", 1);
  sigint_flag = 1;
}

void reap_zombies() {
  int status;
  // pid_t pid;

  while ((waitpid(-1, &status, WNOHANG)) > 0) {
  }
}

void exit_command(char **argus) {
  if (argus[1] == NULL) {
    exit(0);
  } else {

    write(STDERR_FILENO, "exit: " TMA_MSG "\n",
          strlen("exit: ") + strlen(TMA_MSG) + 1);
  }
}

// if (argus[0] != NULL && strcmp(argus[0], "exit") == 0) {
// if (argus[1] == NULL) {

void pwd_command(char **argus) {

  if (argus[1] == NULL) {

    char cwd[BUF_SIZE];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
      write(STDOUT_FILENO, cwd, strlen(cwd));
      write(STDOUT_FILENO, "\n", 1);
    } else {

      write(STDERR_FILENO, "pwd: " GETCWD_ERROR_MSG "\n",
            strlen("pwd: ") + strlen(GETCWD_ERROR_MSG) + 1);
    }

  } else {

    write(STDERR_FILENO, "pwd: " TMA_MSG "\n",
          strlen("pwd: ") + strlen(TMA_MSG) + 1);
  }
}

void cd_command(char **argus) {
    if (argus[2] == NULL) {
        char curr_dir[BUF_SIZE];
        if (getcwd(curr_dir, sizeof(curr_dir)) == NULL) {
            write(STDERR_FILENO, "cd: " GETCWD_ERROR_MSG "\n",
                  strlen("cd: ") + strlen(GETCWD_ERROR_MSG) + 1);
            return;
        }

        char *target = argus[1];
        char *new_dir = NULL;
        char *home_dir = getenv("HOME");

        if (argus[1] == NULL || strcmp(target, "~") == 0) {
            if (home_dir == NULL) {
                struct passwd *password = getpwuid(getuid());
                home_dir = (password) ? password->pw_dir : "";
            }
            new_dir = strdup(home_dir);
        } else if (strcmp(target, "-") == 0) {
            if (prev_dir == NULL) {
                write(STDERR_FILENO, "cd: " CHDIR_ERROR_MSG "\n",
                      strlen("cd: ") + strlen(CHDIR_ERROR_MSG) + 1);
                return;
            }
            new_dir = strdup(prev_dir);
        } else {
            new_dir = strdup(target);
        }

        free(prev_dir);
        prev_dir = strdup(curr_dir);

        if (chdir(new_dir) != 0) {
            write(STDERR_FILENO, "cd: " CHDIR_ERROR_MSG "\n",
                  strlen("cd: ") + strlen(CHDIR_ERROR_MSG) + 1);
        }
        free(new_dir);
    } else {
        write(STDERR_FILENO, "cd: " TMA_MSG "\n",
              strlen("cd: ") + strlen(TMA_MSG) + 1);
    }
}

void help_command(char **argus) {
  if (argus[2] != NULL) {

    write(STDERR_FILENO, "help: " TMA_MSG "\n",
          strlen("help: ") + strlen(TMA_MSG) + 1);
    return;
  }
  if (argus[1] == NULL) {
    char *msgs[] = {
        "exit: " EXIT_HELP_MSG,
        "pwd: " PWD_HELP_MSG,
        "cd: " CD_HELP_MSG,
        "help: " HELP_HELP_MSG,
        "history: " HISTORY_HELP_MSG,
        "other_commands: " EXTERN_HELP_MSG,
        NULL
    };

    for (int i = 0; msgs[i]; i++) {
      write(STDOUT_FILENO, msgs[i], strlen(msgs[i]));
      write(STDOUT_FILENO, "\n", 1);
    }
  } else {

    char *msg;

    if (strcmp(argus[1], "exit") == 0) {
      msg = "exit: " EXIT_HELP_MSG;
    } else if (strcmp(argus[1], "pwd") == 0) {
      msg = "pwd: " PWD_HELP_MSG;
    } else if (strcmp(argus[1], "cd") == 0) {
      msg = "cd: " CD_HELP_MSG;
    } else if (strcmp(argus[1], "help") == 0) {
      msg = "help: " HELP_HELP_MSG;
    } else if (strcmp(argus[1], "history") == 0) {
      msg = "history: " HISTORY_HELP_MSG;
    } else {
      char buff[BUF_SIZE];
      snprintf(buff, BUF_SIZE, "%s: " EXTERN_HELP_MSG, argus[1]);
      msg = buff;
    }

    write(STDOUT_FILENO, msg, strlen(msg));
    write(STDOUT_FILENO, "\n", 1);
  }
}

typedef struct {
  int cmd_no;
  char *cmd_line;

} History;

#define hist_size 10
int command_counter = 0;
History history[hist_size];
int history_count = 0;

void history_command(char **argus) {

  int entries = (history_count < hist_size) ? history_count : hist_size;

  for (int i = entries - 1; i >= 0; i--) {
    int index;

    if (history_count < hist_size) {

      index = i;
    } else {
      index = hist_size - 1 - (entries - 1 - i);
    }

    // int i = cmd % hist_size;

    // char buffer[BUF_SIZE];
    // int len = snprintf(buffer, BUF_SIZE, "%d\t%s\n", history[i].cmd_no,
    //                        history[i].cmd_line);
    // write(STDOUT_FILENO, buffer, len);

    char output[BUF_SIZE];
    int len = snprintf(output, sizeof(output), "%d\t%s\n",
                       history[index].cmd_no, history[index].cmd_line);

    write(STDOUT_FILENO, output, len);
  }
}

void add_history(char *cmd) {
  History new_hist;
  new_hist.cmd_no = command_counter;
  new_hist.cmd_line = strdup(cmd);

  if (new_hist.cmd_line == NULL) {
    return;
  }

  if (history_count < hist_size) {

    history[history_count++] = new_hist;
  } else {
    free(history[0].cmd_line);
    for (int i = 0; i < hist_size - 1; i++) {
      history[i] = history[i + 1];
    }
    history[hist_size - 1] = new_hist;
  }

  command_counter++;
}

void execute_command(char **argus, int background) {

  if (!argus[0]) {
    return;
  }
  if (strcmp(argus[0], "exit") == 0) {
    exit_command(argus);
    return;
  } else if (strcmp(argus[0], "pwd") == 0) {
    pwd_command(argus);
    return;
  } else if (strcmp(argus[0], "cd") == 0) {

    cd_command(argus);
    return;
  } else if (strcmp(argus[0], "history") == 0) {
    history_command(argus);
    return;
  } else if (strcmp(argus[0], "help") == 0) {
    help_command(argus);
    return;
  }

  pid_t pid;

  pid = fork();

  if (pid == -1) {

    write(STDERR_FILENO, "shell: " FORK_ERROR_MSG "\n",
          strlen("shell: ") + strlen(FORK_ERROR_MSG) + 1);
    return;
  } else if (pid == 0) {
    if (execvp(argus[0], argus) == -1) {
        write(STDERR_FILENO, "shell: " EXEC_ERROR_MSG "\n",
              strlen("shell: ") + strlen(EXEC_ERROR_MSG) + 1);
        exit(1);
    }
  } else {
    if (!background) {
      if (waitpid(pid, NULL, 0) == -1) {

        write(STDERR_FILENO, "shell: " WAIT_ERROR_MSG "\n",
              strlen("shell: ") + strlen("shell: " WAIT_ERROR_MSG "\n"));
      }
    }
  }

  reap_zombies();
}

void write_prompt() {
  char cwd[BUF_SIZE];

  if (getcwd(cwd, sizeof(cwd)) != NULL) {
    write(STDOUT_FILENO, cwd, strlen(cwd));

    write(STDOUT_FILENO, "$ ", 2);

  } else {
    write(STDERR_FILENO, "shell: " GETCWD_ERROR_MSG "\n",
          strlen("shell: ") + strlen("shell: " GETCWD_ERROR_MSG "\n"));
    write(STDOUT_FILENO, "$ ", 2);
  }
}

// int read_input(char* buff, ssize_t size

void tokenize_input(char *input, char **argus, int *is_background) {
  char *token = NULL;

  char *delim = " \t\n\r";
  char *pointer = NULL;
  *is_background = 0;

  int argu_count = 0;

  token = strtok_r(input, delim, &pointer);

  while (token && argu_count < TOK_SIZE) {
    argus[argu_count++] = token;
    token = strtok_r(NULL, delim, &pointer);
  }
  argus[argu_count] = NULL;

  /*  for (int i = 0; i < argu_count; i++) {
      printf("%d %s\n", i, argus[i]);
    }*/

  if (argu_count > 0 && strcmp(argus[argu_count - 1], "&") == 0) {
    *is_background = 1;
    argus[--argu_count] = NULL;
    // printf("& triggered\n");
  }
}

/*void trim_whitespace(char *str) {
  size_t length = strlen(str);

  while (len > 0 && isspace(str[len - 1])) {
    str[--len] = '\0';
  }
}*/

int main() {

  char input[BUF_SIZE];
  char command[BUF_SIZE];
  char *argus[TOK_SIZE];
  int background;

  struct sigaction sigact;
  sigact.sa_handler = sigint_handler;
  sigemptyset(&sigact.sa_mask);
  sigact.sa_flags = SA_RESTART;

  sigaction(SIGINT, &sigact, NULL);

  while (42) {
    // while (waitpid(-1, NULL, WNOHANG) > 0)
    reap_zombies();

    // char cwd[BUF_SIZE];

    // write(STDOUT_FILENO, cwd, strlen(cwd));
    // write(STDOUT_FILENO, "$", 1);

    write_prompt();

    ssize_t read_input = read(STDIN_FILENO, input, BUF_SIZE - 1);

    if (sigint_flag == 1) {
      help_command((char *[]){"help", NULL});
      sigint_flag = 0;
      continue;
    }
    if (read_input <= 0) {
      if (errno == EINTR) {
        sigint_flag = 1;
      }

      write(STDERR_FILENO, "shell: " READ_ERROR_MSG "\n",
            strlen("shell: ") + strlen("shell: " READ_ERROR_MSG "\n"));
    }
    input[read_input] = '\0';
    if (read_input > 0) {
      if (input[read_input - 1] == '\n' || input[read_input - 1] == '\r') {
        input[read_input - 1] = '\0';
      }
    }

    strncpy(command, input, BUF_SIZE);
    command[BUF_SIZE - 1] = '\0';

    tokenize_input(input, argus, &background);

    // TODO task1: internal commands and sigint DONE
    // chekc if token matches any internal command
    // exit
    // pwd
    // cd
    // help
    // sigint to catch control c
    // erros for all tjese
    //

    // TODO task2: history feature
    // internal command history. displays 10 most recen t commands
    // ! allows users 2 run commands from hist lsit
    // !n
    // !!
    //
    // long n;
    if (argus[0] != NULL) {

      if (strcmp(argus[0], "!!") == 0) {
        if (history_count == 0) {
          write(STDERR_FILENO, "history: " HISTORY_NO_LAST_MSG "\n",
                strlen("history: ") + strlen(HISTORY_NO_LAST_MSG) + 1);
          continue;
        }
        History entry = history[history_count - 1];
        strncpy(command, entry.cmd_line, BUF_SIZE);
        command[BUF_SIZE - 1] = '\0';
        write(STDOUT_FILENO, command, strlen(command));
        write(STDOUT_FILENO, "\n", 1);
        tokenize_input(command, argus, &background);
      } else if (argus[0][0] == '!') {

        char *end_pointer;
        long n = strtol(argus[0] + 1, &end_pointer, 10);
        if (*end_pointer != '\0' || n < 0 || n >= command_counter) {
          write(STDERR_FILENO, "history: " HISTORY_INVALID_MSG "\n",
                strlen("history: ") + strlen(HISTORY_INVALID_MSG) + 1);
        }

        // add_history(entry.cmd_line);

        // char tmp[BUF_SIZE];
        // char *new_argus[TOK_SIZE];
        // int new_bg;
        // tokenize_input(tmp, new_argus, &new_bg);

        int flag = 0;

        for (int i = 0; i < history_count; i++) {

          if (history[i].cmd_no == n) {
            strncpy(command, history[i].cmd_line, BUF_SIZE);
            command[BUF_SIZE - 1] = '\0';
            tokenize_input(command, argus, &background);
            write(STDOUT_FILENO, command, strlen(command));
            write(STDOUT_FILENO, "\n", 1);

            flag = 1;
            break;
          }
        }

        //   write(STDOUT_FILENO, history[i].cmd_line,
        //   strlen(history[i].cmd_line));
        // write(STDOUT_FILENO, "\n", 1);
        // add_history(history[i].cmd_line);

        // char tmp[BUF_SIZE];
        // strncpy(tmp, history[i].cmd_line, BUF_SIZE);
        // tmp[BUF_SIZE - 1] = '\0';
        // char *new_argu[TOK_SIZE];
        // int new_bg;
        // tokenize_input(tmp, new_argu, &new_bg);
        // execute_command(new_argu, new_bg);
        // flag = 1;
        // break;
        //}
        //}
        if (!flag) {
          write(STDERR_FILENO, "history: " HISTORY_INVALID_MSG "\n",
                strlen("history: ") + strlen(HISTORY_INVALID_MSG) + 1);
        }
      }
      if (argus[0] != NULL) {
        if (argus[0][0] != '!' && strcmp(argus[0], "!!") != 0) {
          add_history(command);
        }
        // add_history(command);
        execute_command(argus, background);
      }

      // execute_command(argus, background);

      //   tokenize_input(input, argus, &background);

      //  input[read_input] = '\0';

      // if (input[read_input - 1] == '\n' || input[read_input - 1] == '\r') {
      //  input[read_input - 1] = '\0';
      //}

      // tokenize_input(input, argus, &background);

      // write("$")
      //

      // char *pointer;
      // char *tok[TOK_SIZE];
      // int tok_count = 0;
      // char *token = strtok_r(input, " ", &pointer);
      //    return 0;

      //
      // TODO task2: history feature
      // internal command history. displays 10 most recen t commands
      // ! allows users 2 run commands from hist lsit
      // !n
      // !!
      //
    }
    // return 0;
  }
  return 0;
}