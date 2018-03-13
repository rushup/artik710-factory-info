/*
 * Copyright (C) 2018 Matteo Fumagalli <m.fumagalli@rushup.tech>
 *
 * Factory Information support for userspace use, ported from Samsung Artik u-boot
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>


#define FACTORY_INFO_HEADER_MAGIC	0x46414354
#define FACTORY_INFO_HEADER_MAJOR	0x0001
#define FACTORY_INFO_HEADER_MINOR	0x0000
#define FACTORY_INFO_OFFSET 0x1c00*512
#define FACTORY_INFO_COUNT  0x100*512
#define FACTORY_DEVICE "/dev/mmcblk0"
#define MAX_ENTITIES 100
#define MAX_DATA 256*512


struct fi_header {
    unsigned int magic;
    unsigned short major;
    unsigned short minor;
    unsigned int total_count;	/* A count of entities */
    unsigned int total_bytes;	/* Last position of buffer */
};

struct fi_entity_header {
    unsigned int name_len;
    unsigned int val_len;
};

struct fi_entity {
    struct fi_entity_header e_hdr;
    char *name;
    char *val;
};

static struct fi_entity* f_entities[MAX_ENTITIES];
static struct fi_header f_hdr;
static char buffer[MAX_DATA];
static int info_loaded;


static void factory_header_init(struct fi_header *hdr) {
    hdr->magic = FACTORY_INFO_HEADER_MAGIC;
    hdr->major = FACTORY_INFO_HEADER_MAJOR;
    hdr->minor = FACTORY_INFO_HEADER_MINOR;
    hdr->total_count = 0;
    hdr->total_bytes = sizeof(struct fi_header);
}

static int check_header(struct fi_header *hdr) {
    if (hdr->magic != FACTORY_INFO_HEADER_MAGIC)
        return -1;

    if (hdr->major != FACTORY_INFO_HEADER_MAJOR ||
        hdr->minor != FACTORY_INFO_HEADER_MINOR)
        return -1;

    return 0;
}

static inline char *alloc_string(const char *buf, int len) {
    char *new_str = malloc(len + 1);
    memcpy(new_str, buf, len);
    new_str[len] = 0;

    return new_str;
}

static struct fi_entity *alloc_new_entity(const char *name, int name_len, const char *val, int val_len) {
    struct fi_entity *entity = malloc(sizeof(struct fi_entity));
    entity->e_hdr.name_len = name_len;
    entity->e_hdr.val_len = val_len;
    entity->name = alloc_string(name, name_len);
    entity->val = alloc_string(val, val_len);
    return entity;
}

static struct fi_entity *find_entity(const char *entity_name) {
    struct fi_entity *pos;

    for(uint8_t i=0; i < MAX_ENTITIES; i++)
    {
        if(f_entities[i] != 0 && strcmp(f_entities[i]->name, entity_name) == 0)
            return f_entities[i];
    }

    return NULL;
}

/* Parse entities from memory buffer */
static int fi_deserialize(char *buf) {
    struct fi_entity *entity;
    struct fi_entity_header hdr;
    int i, offset = 0;

    memcpy(&f_hdr, buf, sizeof(struct fi_header));

    if (check_header(&f_hdr))
        factory_header_init(&f_hdr);

    offset += sizeof(struct fi_header);

    for (i = 0; i < f_hdr.total_count; i++) {
        memcpy(&hdr, buf + offset, sizeof(struct fi_entity_header));
        offset += sizeof(struct fi_entity_header);

        entity = alloc_new_entity(buf + offset, hdr.name_len,
                buf + offset + hdr.name_len, hdr.val_len);

        f_entities[i] = entity;

        offset += hdr.name_len + hdr.val_len;
    }

    f_hdr.total_bytes = offset;

    info_loaded = 1;

    return 0;
}

/* Store entities into memory buffer */
static void fi_serialize(char *buf) {
    int offset = 0;
    uint8_t i;
    struct fi_entity *pos;

    offset = sizeof(struct fi_header);

    for(i=0; i < MAX_ENTITIES; i++) {
        if(f_entities[i] != NULL)
        {
            memcpy(buf + offset, &f_entities[i]->e_hdr,
                   sizeof(struct fi_entity_header));
            offset += sizeof(struct fi_entity_header);
            memcpy(buf + offset, f_entities[i]->name, f_entities[i]->e_hdr.name_len);
            offset += f_entities[i]->e_hdr.name_len;
            memcpy(buf + offset, f_entities[i]->val, f_entities[i]->e_hdr.val_len);
            offset += f_entities[i]->e_hdr.val_len;

        }
    }

    f_hdr.total_bytes = offset;
    memcpy(buf, &f_hdr, sizeof(struct fi_header));
}

static void factory_info_destroy(void) {
    struct fi_entity *pos, *tmp;
    uint8_t i;

    for(i=0; i < MAX_ENTITIES; i++) {
        if(f_entities[i] != NULL) {
            free(f_entities[i]->name);
            free(f_entities[i]->val);
            free(f_entities[i]);
            f_entities[i] = NULL;
        }
    }


    factory_header_init(&f_hdr);
}

static int factory_info_load(const char *interface, uint32_t offset, uint32_t count) {
    int err, size;
    FILE* fdes;

    if (info_loaded)
        factory_info_destroy();

    fdes = fopen(interface, "rb");

    if(fdes >= 0)
    {
        fseek(fdes, offset, SEEK_SET);
        size = fread(buffer, 1, count, fdes);

        fclose(fdes);

        return fi_deserialize((char *)buffer);
    }
    else
        return -1;
}

static int factory_info_save(const char *interface, uint32_t offset, uint32_t count) {
    int err, size;
    FILE* fdes;

    if (!info_loaded) {
        printf("Please load the information at first\n");
        return -1;
    }

    fi_serialize((char *)buffer);

    fdes = fopen(interface, "wb");

    if(fdes >= 0)
    {
        fseek(fdes, offset, SEEK_SET);
        size = fwrite(buffer, 1, count, fdes);

        fclose(fdes);

        if(size == count)
            return 1;
        else
            return -1;
    }
    else
        return -1;


    return 0;
}

static int factory_info_read_entity(const char *entity_name) {
    struct fi_entity *entity;

    if (!info_loaded) {
        printf("Please load the information at first\n");
        return -1;
    }

    entity = find_entity(entity_name);
    if (entity) {
        printf("%s\n", entity->val);
        return 0;
    }

    return -1;
}

static void update_entity_value(struct fi_entity *entity, const char *value) {
    free(entity->val);
    entity->e_hdr.val_len = strlen(value);
    entity->val = alloc_string(value, entity->e_hdr.val_len);
}

static int factory_info_write_entity(const char *entity_name, const char *value) {
    struct fi_entity *entity;

    if (!info_loaded) {
        printf("Please load the information at first\n");
        return -1;
    }

    entity = find_entity(entity_name);
    if (entity) {
        update_entity_value(entity, value);
    } else {
        entity = alloc_new_entity(entity_name, strlen(entity_name),
                value, strlen(value));

        f_entities[f_hdr.total_count] = entity;

        f_hdr.total_count++;
        f_hdr.total_bytes += sizeof(struct fi_entity_header) +
            entity->e_hdr.name_len + entity->e_hdr.val_len;
    }

    return 0;
}

static int factory_info_genethaddr(char can_be_overwritten) {
    const char *entity_name = "ethaddr";
    struct fi_entity *entity;
    unsigned long ethaddr_low, ethaddr_high;
    char tmp[18];
    FILE* fpwlan;
    char macwlan[18];
    int macwlanint[6];
    uint32_t mac;

    entity = find_entity(entity_name);

    if(entity == NULL || can_be_overwritten == 1)
    {

        // Take randomness from MAC ID if possibile
        fpwlan = fopen("/sys/class/net/wlan0/address", "r");
        if(fpwlan >= 0)
        {
            fread(macwlan, 1, 18, fpwlan);
            fclose(fpwlan);
            if(sscanf(macwlan, "%x:%x:%x:%x:%x:%x",
                   &macwlanint[0],
                   &macwlanint[1],
                   &macwlanint[2],
                   &macwlanint[3],
                   &macwlanint[4],
                   &macwlanint[5]) == 6)
            {
                // Skipping 70:2C
                mac = macwlanint[2] |
                      macwlanint[3] << 8 |
                      macwlanint[4] << 16 |
                      macwlanint[5] << 24;
                srand(time(0) * mac);

            }
            else
            {
                printf("mac read failed, only using time seed\n");
                srand(time(0));
            }

        }
        else
        {
            printf("wlan0 not found, only using time seed\n");
            srand(time(0));
        }


        /*
         * setting the 2nd LSB in the most significant byte of
         * the address makes it a locally administered ethernet
         * address
         */
        ethaddr_high = (rand() & 0xfeff) | 0x0200;
        ethaddr_low = rand();


        sprintf(tmp, "%02lx:%02lx:%02lx:%02lx:%02lx:%02lx",
            ethaddr_high >> 8, ethaddr_high & 0xff,
            ethaddr_low >> 24, (ethaddr_low >> 16) & 0xff,
            (ethaddr_low >> 8) & 0xff, ethaddr_low & 0xff);

        return factory_info_write_entity(entity_name, tmp);
    }
    else
    {
        //printf("Skipping write ethaddr \n");
        return -1;
    }

}

static int factory_info_list(void) {
    struct fi_entity *pos;
    uint8_t i;

    if (!info_loaded) {
        printf("Please load the information at first\n");
        return -1;
    }

    for(i=0; i < MAX_ENTITIES; i++)
    {
        if(f_entities[i] != NULL)
            printf("%s %s\n", f_entities[i]->name, f_entities[i]->val);

    }

    return 0;
}

static int factory_info_clean(void) {
    if (!info_loaded) {
        printf("Please load the information at first\n");
        return -1;
    }

    factory_info_destroy();

    return 0;
}

int do_factory_info(int argc, char * const argv[])
{
    switch (argc) {
    case 4:
        if (!strncmp(argv[1], "write", 5)) {
            factory_info_write_entity(argv[2], argv[3]);
            factory_info_save(FACTORY_DEVICE, FACTORY_INFO_OFFSET, FACTORY_INFO_COUNT);
            break;
        }
    case 3:
        if (!strncmp(argv[1], "read", 4))
        {
            factory_info_read_entity(argv[2]);
            break;
        }
    case 2:
        if (!strncmp(argv[1], "list", 4)) {
            factory_info_list();
            break;
        }
        else if (!strncmp(argv[1], "clean", 5)) {
            factory_info_clean();
            factory_info_save(FACTORY_DEVICE, FACTORY_INFO_OFFSET, FACTORY_INFO_COUNT);
            break;
        }
        else if (!strcmp(argv[1], "gen_ethaddr")) {
            factory_info_genethaddr(1);
            factory_info_save(FACTORY_DEVICE, FACTORY_INFO_OFFSET, FACTORY_INFO_COUNT);
            break;
        }
        else if (!strcmp(argv[1], "gen_ethaddr_once")) {
            factory_info_genethaddr(0);
            factory_info_save(FACTORY_DEVICE, FACTORY_INFO_OFFSET, FACTORY_INFO_COUNT);
            break;
        }

    case 1:
    default:
        return 1;
    }

    return 0;
}

const char* help = {
       "Factory Information commands\n"
       "factory_info list - List factory information\n"
       "factory_info read <entity name> - Read a value of entity name\n"
       "factory_info write <entity name> <val> - Write a value of entity name\n"
       "factory_info gen_ethaddr - Generate random local ethernet mac address\n"
       "factory_info gen_ethaddr_once - Generate ethaddr only if not present\n"
       "factory_info clean - Clean factioy information\n"
};


int main(int argc, char *argv[]) {
    memset(f_entities, 0, sizeof(char*)*MAX_ENTITIES);
    factory_info_load(FACTORY_DEVICE, FACTORY_INFO_OFFSET, FACTORY_INFO_COUNT);

    if(do_factory_info(argc,argv))
        printf("%s", help);
    return 0;
}
