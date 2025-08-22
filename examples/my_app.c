#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>

static volatile int run = 1;
static void handle(int s){ (void)s; run = 0; }

int main(void){
    prctl(PR_SET_DUMPABLE, 0);
    prctl(PR_SET_PTRACER, -1);
    signal(SIGINT, handle); signal(SIGTERM, handle);

    printf("[my_app] started (PID=%d). Running for 300s...\\n", getpid());
    fflush(stdout);

    for(int i=0;i<300 && run;i++){
        printf("[my_app] tick %d/300\\n", i+1);
        fflush(stdout);
        sleep(1);
    }

    printf("[my_app] exiting cleanly.\\n");
    fflush(stdout);
    return 0;
}
