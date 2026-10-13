#include "test.h"

#include "zapc/history.h"
#include "zapc/platform.h"
#include "zapc/storage.h"

#include <sys/stat.h>
#include <unistd.h>

static char g_dir[128];

static void test_credentials_roundtrip(void)
{
    wa_device d, e;
    CHECK(credentials_load(&e) == 1); /* nothing yet */
    CHECK(wa_device_generate(&d) == 0);
    d.paired = 1;
    jid_parse(&d.jid, "5511999990000:7@s.whatsapp.net");
    jid_parse(&d.lid, "123456:7@lid");
    snprintf(d.platform, sizeof d.platform, "android");
    snprintf(d.push_name, sizeof d.push_name, "Jo\xc3\xa3o");
    memset(d.account, 0xAB, 300);
    d.account_len = 300;
    d.next_prekey_id = 77;
    d.uploaded_prekey_id = 70;
    CHECK(credentials_save(&d) == 0);

    char path[256];
    struct stat st;
    storage_path(path, sizeof path, "credentials.bin");
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    CHECK(stat(g_dir, &st) == 0 && (st.st_mode & 0777) == 0700);

    CHECK(credentials_load(&e) == 0);
    CHECK_MEM(e.noise_key.priv, d.noise_key.priv, 32);
    CHECK_MEM(e.identity_key.pub, d.identity_key.pub, 32);
    CHECK_MEM(e.signed_prekey_sig, d.signed_prekey_sig, 64);
    CHECK(e.registration_id == d.registration_id);
    CHECK(e.paired && e.jid.device == 7 && strcmp(e.jid.user, "5511999990000") == 0);
    CHECK_STR(e.lid.server, "lid");
    CHECK_STR(e.platform, "android");
    CHECK_STR(e.push_name, "Jo\xc3\xa3o");
    CHECK(e.account_len == 300 && e.account[299] == 0xAB);
    CHECK(e.next_prekey_id == 77 && e.uploaded_prekey_id == 70);

    /* corrupt file is rejected, not half-loaded */
    uint8_t junk[40];
    memset(junk, 0x11, sizeof junk);
    memcpy(junk, "ZAPC\x00\x01", 6);
    plat_write_file_atomic(path, junk, sizeof junk, 0600);
    CHECK(credentials_load(&e) == -1);
    CHECK(credentials_save(&d) == 0);
}

static void test_prekeys(void)
{
    uint8_t k1[32], k2[32], out[32];
    memset(k1, 1, 32);
    memset(k2, 2, 32);
    CHECK(prekeys_append(10, k1) == 0);
    CHECK(prekeys_append(11, k2) == 0);
    CHECK(prekeys_count() == 2);
    CHECK(prekeys_find(11, out) == 0 && memcmp(out, k2, 32) == 0);
    CHECK(prekeys_remove(10) == 0);
    CHECK(prekeys_find(10, out) != 0);
    CHECK(prekeys_count() == 1);
}

static void test_blobs(void)
{
    uint8_t buf[16];
    CHECK(storage_blob_save("sessions", "5511:3", "abc", 3) == 0);
    CHECK(storage_blob_load("sessions", "5511:3", buf, sizeof buf) == 3);
    CHECK(storage_blob_load("sessions", "../credentials.bin", buf, sizeof buf) < 0);
    CHECK(storage_blob_save("sessions", "a/b", "x", 1) != 0);
    CHECK(storage_blob_delete("sessions", "5511:3") == 0);
    CHECK(storage_blob_load("sessions", "5511:3", buf, sizeof buf) < 0);
}

static void test_history_log(void)
{
    wa_message m, out[ZAPC_VISIBLE_MESSAGES];
    wa_jid chat;
    jid_parse(&chat, "5511888887777@s.whatsapp.net");
    for (int i = 0; i < 100; i++) {
        memset(&m, 0, sizeof m);
        m.chat = chat;
        m.sender = chat;
        m.from_me = i % 2;
        m.timestamp = 1000 + i;
        snprintf(m.id, sizeof m.id, "ID%d", i);
        snprintf(m.text, sizeof m.text, "mensagem %d\nlinha 2", i);
        snprintf(m.push_name, sizeof m.push_name, "Maria");
        CHECK(history_append(&m) == 0);
    }
    CHECK(history_count(&chat) == 100);
    long first;
    int n = history_load(&chat, -1, out, 10, &first);
    CHECK(n == 10 && first == 90);
    CHECK_STR(out[0].text, "mensagem 90\nlinha 2");
    CHECK_STR(out[9].id, "ID99");
    CHECK(out[9].from_me == 1 && out[9].timestamp == 1099);
    CHECK_STR(out[9].push_name, "Maria");
    n = history_load(&chat, 5, out, 10, &first); /* older block */
    CHECK(n == 5 && first == 0);
    CHECK_STR(out[4].id, "ID4");
    wa_jid other;
    jid_parse(&other, "1@s.whatsapp.net");
    CHECK(history_count(&other) == 0);
    CHECK(history_load(&other, -1, out, 10, &first) == 0);
}

static void test_chats_contacts(void)
{
    chat_list cl;
    contact_list ct;
    wa_jid a, b;
    chats_load(&cl);
    CHECK(cl.count == 0);
    jid_parse(&a, "111@s.whatsapp.net");
    jid_parse(&b, "120363@g.us");
    chat_entry *e = chats_touch(&cl, &a);
    e->last_ts = 10;
    snprintf(e->name, sizeof e->name, "Ana");
    e = chats_touch(&cl, &b);
    e->last_ts = 20;
    e->unread = 3;
    snprintf(e->preview, sizeof e->preview, "oi");
    CHECK(chats_touch(&cl, &a)->last_ts == 10); /* found, not duplicated */
    CHECK(cl.count == 2);
    CHECK(chats_save(&cl) == 0);
    chats_load(&cl);
    CHECK(cl.count == 2);
    chats_sort(&cl);
    CHECK(jid_is_group(&cl.chats[0].jid) && cl.chats[0].unread == 3);
    CHECK_STR(cl.chats[1].name, "Ana");

    /* fill beyond capacity: the oldest chat is evicted */
    for (int i = 0; i < ZAPC_MAX_CHATS + 5; i++) {
        wa_jid j;
        char s[32];
        snprintf(s, sizeof s, "9%d@s.whatsapp.net", i);
        jid_parse(&j, s);
        chats_touch(&cl, &j)->last_ts = 100 + i;
    }
    CHECK(cl.count == ZAPC_MAX_CHATS);

    contacts_load(&ct);
    contacts_set(&ct, &a, "Ana Paula");
    contacts_set(&ct, &a, "Ana");
    CHECK(ct.count == 1);
    CHECK(contacts_save(&ct) == 0);
    contacts_load(&ct);
    CHECK_STR(contacts_get(&ct, &a), "Ana");
    CHECK(contacts_get(&ct, &b) == NULL);
}

int main(void)
{
    snprintf(g_dir, sizeof g_dir, "/tmp/zapc-st-%d", (int)getpid());
    if (storage_init(g_dir) != 0)
        return 1;
    RUN(test_credentials_roundtrip);
    RUN(test_prekeys);
    RUN(test_blobs);
    RUN(test_history_log);
    RUN(test_chats_contacts);
    char cmd[200];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0)
        fprintf(stderr, "cleanup failed\n");
    return test_done("test_storage");
}
