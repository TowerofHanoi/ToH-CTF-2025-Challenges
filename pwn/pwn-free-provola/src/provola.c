#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define MAX_PROVOLAS 32
#define MAX_REVIEW_LENGTH 0x800

typedef struct Provola {
    char name[64];     
    int  rating;       
    char *review;
    int review_length;     
} Provola;

Provola *provolas[MAX_PROVOLAS];
int provola_count = 0;


void menu(void) {
    puts("=========== Provola Review ===========");
    puts("[1] add review");
    puts("[2] list reviews");
    puts("[3] delete review");
    puts("[4] edit review");
    puts("[5] exit");
}

void read_n(char *buf, size_t n) {
    ssize_t r = read(0, buf, n - 1);
    if (r <= 0) exit(1);
    if (buf[r - 1] == '\n')
        buf[r - 1] = 0;
    else
        buf[r] = 0;
}

void add_review(void) {
    char tmp[16];


    if (provola_count >= MAX_PROVOLAS) {
        puts("Sorry, review list full!\n");
        return;
    }

    Provola *p = malloc(sizeof(Provola));
    if (!p) {
        puts("malloc failed");
        exit(1);
    }

    printf("name: ");
    read_n(p->name, sizeof(p->name));

    printf("rating (1-10): ");
    read_n(tmp, sizeof(tmp));
    p->rating = atoi(tmp);
    if (p->rating < 1 || p->rating > 10) {
        puts("Invalid rating - setting to 1\n");
        p->rating = 1;
    }

    printf("review length (max %d): ", MAX_REVIEW_LENGTH);
    read_n(tmp, sizeof(tmp));
    size_t len = strtoul(tmp, NULL, 10);
    if (!len || len > MAX_REVIEW_LENGTH)
        len = MAX_REVIEW_LENGTH;

    p->review_length = len;
    p->review = malloc(len + 1);
    if (!p->review) {
        puts("malloc failed");
        exit(1);
    }

    printf("review: ");
    ssize_t r = read(0, p->review, len);
    if (r <= 0) {
        puts("read failed");
        exit(1);
    }
    p->review[r] = 0;

    provolas[provola_count++] = p;
    puts("review added!\n");
}

void list_reviews(void) {
    if (!provola_count) {
        puts("no reviews yet!\n");
        return;
    }

    for (int i = 0; i < provola_count; ++i) {
        Provola *p = provolas[i];
        if (!p) continue;
        printf("%d. %s - rating: %d/10\n", i, p->name, p->rating);
        puts("   review:");
        puts(p->review);
        puts("");
    }
}

void delete_review(void) {
    if (!provola_count) {
        puts("nothing to delete!\n");
        return;
    }

    printf("id to delete: ");
    char tmp[16];
    read_n(tmp, sizeof(tmp));
    int id = atoi(tmp);

    if (id < 0 || id >= provola_count || !provolas[id]) {
        puts("invalid id\n");
        return;
    }

    Provola *p = provolas[id];
    free(p->review);
    free(p);
    puts("deleted!\n");
}


void edit_review(void) {
    if (!provola_count) {
        puts("no reviews to edit!\n");
        return;
    }

    printf("id to edit: ");
    char tmp[16];
    read_n(tmp, sizeof(tmp));
    int id = atoi(tmp);

    if (id < 0 || id >= provola_count || !provolas[id]) {
        puts("invalid id\n");
        return;
    }

    Provola *p = provolas[id];
    printf("new review for %s: ", p->name);
    
    ssize_t r = read(0, p->review, p->review_length);
    if (r <= 0) {
        puts("read failed");
        exit(1);
    }
    p->review[r] = 0;

    puts("review updated!\n");
}

void ignore_buffering() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(void) {
    ignore_buffering();

    while (1) {
        menu();
        printf("> ");
        char buf[16];
        read_n(buf, sizeof(buf));
        int choice = atoi(buf);
        switch (choice) {
            case 1:  add_review();     break;
            case 2:  list_reviews();   break;
            case 3:  delete_review();  break;
            case 4:  edit_review();    break;
            case 5:  puts("bye!");    exit(0);
            default: puts("invalid choice\n");
        }
    }
}
