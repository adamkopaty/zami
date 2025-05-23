#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Użycie: %s polecenie [argumenty...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Pobranie informacji o użytkowniku "grafi"
    struct passwd *pwd = getpwnam("grafi");
    if (pwd == NULL) {
        perror("Nie można odnaleźć użytkownika grafi");
        return EXIT_FAILURE;
    }

    // Ustawienie UID na użytkownika "grafi"
    if (setuid(pwd->pw_uid) != 0) {
        perror("setuid nie powiodło się");
        return EXIT_FAILURE;
    }

    // Wykonanie polecenia podanego jako parametr
    execvp(argv[1], &argv[1]);
    perror("execvp nie powiodło się");
    return EXIT_FAILURE;
}