#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>


#define FLIGHT_LEN 5
#define FLIGHT_SIZE (FLIGHT_LEN + 1)
#define REFERENCE_SIZE 8
#define COMPLAINT_SIZE 256
#define NAME_LEN 8
#define NAME_SIZE (NAME_LEN + 1)
#define MAX_RECORDS 16

typedef struct {
    char* name;
    char* reference;
    char* flight;
    bool checked_in;
} Booking;

typedef struct {
    Booking* related_booking;
    char complaint[COMPLAINT_SIZE];
} Complaint;

Booking* bookings[MAX_RECORDS];
Complaint* complaints[MAX_RECORDS];
int booking_count = 0;
int complaint_count = 0;

void consume_stdin() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void ignore_buffering() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void menu() {
    puts("----------| CAC |----------");
    puts("[1] Add Booking reference");
    puts("[2] Check in");
    puts("[3] Booking info");
    puts("[4] Customer complaint");
    puts("[5] Edit complaint");
    puts("[6] Book flight");
    puts("[7] Exit");
}

bool check_flight_number(char* flight) {
    if (strlen(flight) != FLIGHT_LEN || memcmp(flight, "CC", 2) != 0) return false;
    for (int i = 2; i < FLIGHT_LEN; i++) 
        if (flight[i] < '0' || flight[i] > '9') return false;
    return true;
}

void cleanup() {
    for (int i = 0; i < booking_count; i++) {
        if (bookings[i]) {
            free(bookings[i]->reference);
            free(bookings[i]->flight);
            free(bookings[i]->name);
            free(bookings[i]);
            bookings[i] = NULL;
        }
    }
    for (int i = 0; i < complaint_count; i++) {
        free(complaints[i]);
        complaints[i] = NULL;
    }
}


void add_booking() {
    if (booking_count >= MAX_RECORDS) {
        puts("Cannot add more bookings.");
        return;
    }

    Booking* new_booking = malloc(sizeof(Booking));
    if (!new_booking) {
        puts("Memory allocation failed.");
        return;
    }
    
    if (!(new_booking->reference = malloc(REFERENCE_SIZE)) || 
        !(new_booking->flight = malloc(FLIGHT_SIZE))       || 
        !(new_booking->name = malloc(NAME_SIZE))) { 
            puts("Out of memory."); 
            free(new_booking); 
            return; 
    }

    printf("Enter reference number (exactly 8 characters):\n> ");
    fread(new_booking->reference, 1, REFERENCE_SIZE, stdin);
    consume_stdin();

    printf("Enter flight number (exactly %d characters, e.g., CC123):\n> ", FLIGHT_LEN);
    fread(new_booking->flight, 1, FLIGHT_LEN, stdin);
    consume_stdin();
    new_booking->flight[FLIGHT_LEN] = '\0';


    if (!check_flight_number(new_booking->flight)) {
        puts("Invalid flight number.");
        free(new_booking->reference);
        free(new_booking->flight);
        free(new_booking->name);
        free(new_booking);
        return;
    }

    printf("Enter your name (max %d chars):\n> ", NAME_LEN);
    fgets(new_booking->name, NAME_SIZE, stdin);
    new_booking->name[strcspn(new_booking->name, "\n")] = '\0';

    new_booking->checked_in = false;
    bookings[booking_count++] = new_booking;
    puts("Booking successfully added.");
}

void check_in() {
    char reference[REFERENCE_SIZE];
    printf("Enter your 8-byte booking reference:\n> ");
    fread(reference, 1, REFERENCE_SIZE, stdin);
    consume_stdin();

    for (int i = 0; i < booking_count; i++) {
        if (bookings[i] && memcmp(bookings[i]->reference, reference, REFERENCE_SIZE) == 0) {
            if (bookings[i]->checked_in) {
                puts("You have already checked in.");
            } else {
                bookings[i]->checked_in = true;
                printf("Checked in successfully for %s!\n", bookings[i]->name);
            }
            return;
        }
    }
    puts("Booking reference not found.");
}

void booking_info() {
    char reference[REFERENCE_SIZE];
    printf("Please enter the 8-byte reference number:\n> ");
    fread(reference, 1, REFERENCE_SIZE, stdin);
    consume_stdin();

    for (int i = 0; i < booking_count; i++) {
        if (bookings[i] && memcmp(bookings[i]->reference, reference, REFERENCE_SIZE) == 0) {
            printf("Booking found:\n"
                    "Reference: %.*s\n"
                    "Name: %s\n"
                    "Flight: %s\n"
                    "Checked in: %s\n",
                    REFERENCE_SIZE, bookings[i]->reference,
                    bookings[i]->name,
                    bookings[i]->flight,
                    bookings[i]->checked_in ? "Yes" : "No");

            return;
        }
    }
    puts("Booking not found.");
}

void customer_complaint() {
    if (complaint_count >= MAX_RECORDS) {
        puts("Maximum complaints reached.");
        return;
    }

    char reference[REFERENCE_SIZE];
    char complaint_tmp[COMPLAINT_SIZE * 2];

    printf("Please enter the 8-byte reference number related to the complaint:\n> ");
    fread(reference, 1, REFERENCE_SIZE, stdin);
    consume_stdin();

    Booking* matched = NULL;
    for (int i = 0; i < booking_count; i++) {
        if (bookings[i] && memcmp(bookings[i]->reference, reference, REFERENCE_SIZE) == 0) {
            matched = bookings[i];
            break;
        }
    }

    if (!matched) {
        puts("No such Booking found. Complaint rejected.");
        return;
    }

    printf("Enter your complaint (will be truncated to %d characters):\n> ", COMPLAINT_SIZE - 1);
    fgets(complaint_tmp, sizeof(complaint_tmp), stdin);

    Complaint* new_complaint = malloc(sizeof(Complaint));
    if (!new_complaint) {
        puts("Memory allocation failed.");
        return;
    }

    new_complaint->related_booking = matched;
    
    int len = snprintf(new_complaint->complaint, COMPLAINT_SIZE, "%s - Complaint ID: %d", complaint_tmp, complaint_count);
    new_complaint->complaint[len] = '\0';
    complaints[complaint_count++] = new_complaint;

    printf("Thank you for your feedback, %s. Your complaint has been registered with complaint ID: %d.\n", 
        matched->name, complaint_count - 1);
}

void edit_complaint() {
    int complaint_id;
    char complaint_tmp[COMPLAINT_SIZE * 2];

    printf("Please enter the complaint ID:\n> ");
    if (scanf("%d", &complaint_id) != 1) {
        puts("Invalid input.");
        return;
    }
    consume_stdin();

    if (complaint_id < 0 || complaint_id >= complaint_count) {
        puts("Invalid complaint ID.");
        return;
    }
    if (complaints[complaint_id] == NULL) {
        puts("Complaint not found.");
        return;
    }

    Complaint* matched = complaints[complaint_id];
    if (!matched) {
        puts("Complaint not found.");
        return;
    }

    printf("Enter your updated complaint (truncated to %d characters):\n> ", COMPLAINT_SIZE - 1);
    fgets(complaint_tmp, sizeof(complaint_tmp), stdin);

    int len = snprintf(matched->complaint, COMPLAINT_SIZE, "%s - Complaint ID: %d", complaint_tmp, complaint_id);
    matched->complaint[len] = '\0';
    puts("Complaint updated successfully!");
}

void book_flight() {
    if (booking_count >= MAX_RECORDS) {
        puts("Cannot book more flights.");
        return;
    }

    Booking* new_booking = malloc(sizeof(Booking));
    if (!new_booking) {
        puts("Memory allocation failed.");
        return;
    }

    if (!(new_booking->reference = malloc(REFERENCE_SIZE)) || 
        !(new_booking->flight = malloc(FLIGHT_SIZE))       || 
        !(new_booking->name = malloc(NAME_SIZE))) { 
            puts("Out of memory."); 
            free(new_booking); 
            return; 
    }



    for (int i = 0; i < REFERENCE_SIZE; i++) {
        new_booking->reference[i] = 'A' + (rand() % 26);
    }

    new_booking->flight[0] = 'C';
    new_booking->flight[1] = 'C';
    for (int i = 2; i < FLIGHT_LEN; i++) {
        new_booking->flight[i] = '0' + (rand() % 10);
    }

    new_booking->flight[FLIGHT_LEN] = '\0';
    printf("Enter your name (max %d chars):\n> ", NAME_LEN);
    fgets(new_booking->name, NAME_SIZE, stdin);
    new_booking->name[strcspn(new_booking->name, "\n")] = '\0';

    printf("Booking added!\n"
        "Thank you for choosing us, %s!\n"
        "Reference: %.*s\n"
        "Flight: %s\n"
        "Name: %s\n",
        new_booking->name, REFERENCE_SIZE, new_booking->reference, new_booking->flight, new_booking->name);
    
    new_booking->checked_in = false;
    bookings[booking_count++] = new_booking;
}

int main() {
    ignore_buffering();
    int choice;

    puts("Welcome to CAC airlines!");
    printf("As a welcome gift, you will receive a free pointer: %p\n", &book_flight);

    while (1) {
        menu();
        printf("> ");
        if (scanf("%d", &choice) != 1) break;
        consume_stdin();
        switch (choice) {
            case 1: add_booking(); break;
            case 2: check_in(); break;
            case 3: booking_info(); break;
            case 4: customer_complaint(); break;
            case 5: edit_complaint(); break;
            case 6: book_flight(); break;
            case 7: puts("Thank you for using CAC airlines!"); cleanup(); return 0;
            default: puts("Invalid choice.");
        }
    }
    cleanup();
    return 0;
}
