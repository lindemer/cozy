#ifdef COSE_SELF_TEST

#define COSE_TEST_KEY_256_PRIV                                                  \
    "-----BEGIN EC PRIVATE KEY-----\r\n"                                        \
    "MHcCAQEEIKw78CnaOuvcRE7dcngmKcbM6FbB3Ue3wkPYQbu+hNHeoAoGCCqGSM49\r\n"      \
    "AwEHoUQDQgAEAWScYjUwMrXA0gAc/LD6EDmJu7Ob7LzngEVn9HJrj4zGUjELTUYf\r\n"      \
    "Mq2CXK9SpGLX33eRmv9itRcWjWWmqZuh2w==\r\n"                                  \
    "-----END EC PRIVATE KEY-----\r\n"

#define COSE_TEST_KEY_256_PUB                                                   \
    "-----BEGIN PUBLIC KEY-----\r\n"                                            \
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAWScYjUwMrXA0gAc/LD6EDmJu7Ob\r\n"      \
    "7LzngEVn9HJrj4zGUjELTUYfMq2CXK9SpGLX33eRmv9itRcWjWWmqZuh2w==\r\n"          \
    "-----END PUBLIC KEY-----\r\n"

#define COSE_TEST_KEY_384_PRIV                                                  \
    "-----BEGIN EC PRIVATE KEY-----\r\n"                                        \
    "MIGkAgEBBDBf6q2n/6Yu09NpdPYIOcprVVxG97FxrBKeBONnjMTpqAiKTgRBlia6\r\n"      \
    "dmvcPfyeJoSgBwYFK4EEACKhZANiAARiUvCjk5UfrvboapTkXvmJkxGKSnTMVkqD\r\n"      \
    "Y+e/4RJU372TgqnEfLPUf1AskISSkFTWLIOPaj5uHLD67G3FJaue4gQr4jyr/7z0\r\n"      \
    "ScMqQVqbV1KrAjdbHnxtPTw/0q5vA9I=\r\n"                                      \
    "-----END EC PRIVATE KEY-----\r\n"

#define COSE_TEST_KEY_384_PUB                                                   \
    "-----BEGIN PUBLIC KEY-----\r\n"                                            \
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEYlLwo5OVH6726GqU5F75iZMRikp0zFZK\r\n"      \
    "g2Pnv+ESVN+9k4KpxHyz1H9QLJCEkpBU1iyDj2o+bhyw+uxtxSWrnuIEK+I8q/+8\r\n"      \
    "9EnDKkFam1dSqwI3Wx58bT08P9KubwPS\r\n"                                      \
    "-----END PUBLIC KEY-----\r\n"

#define COSE_TEST_KEY_128_SYM                                                   \
    { 0xa9, 0x48, 0x90, 0x4f, 0x2f, 0x0f, 0x47, 0x9b,                           \
      0x8f, 0x81, 0x97, 0x69, 0x4b, 0x30, 0x18, 0x4b };

#define COSE_TEST_KEY_256_SYM                                                   \
    { 0xa9, 0x48, 0x90, 0x4f, 0x2f, 0x0f, 0x47, 0x9b,                           \
      0x8f, 0x81, 0x97, 0x69, 0x4b, 0x30, 0x18, 0x4b,                           \
      0x0d, 0x2e, 0xd1, 0xc1, 0xcd, 0x2a, 0x1e, 0xc0,                           \
      0xfb, 0x85, 0xd2, 0x99, 0xa1, 0x92, 0xa4, 0x47 };

#define COSE_TEST_IV                                                            \
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,                                       \
      0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b };

#define COSE_TEST_PLD                                                           \
    "To be, or not to be, that is the question:\n"                              \
    "Whether 'tis nobler in the mind to suffer\n"                               \
    "The slings and arrows of outrageous fortune,\n"                            \
    "Or to take Arms against a Sea of troubles,\n"                              \
    "And by opposing end them: to die, to sleep;\n"                             \
    "No more; and by a sleep, to say we end\n"                                  \
    "The heart-ache, and the thousand natural shocks\n"                         \
    "That Flesh is heir to? 'Tis a consummation\n"                              \
    "Devoutly to be wished. To die, to sleep,\n"                                \
    "perchance to Dream; aye, there's the rub,\n"                               \
    "For in that sleep of death, what dreams may come,\n"                       \
    "When we have shuffled off this mortal coil,\n"                             \
    "Must give us pause. There's the respect\n"                                 \
    "That makes Calamity of so long life:\n"                                    \
    "For who would bear the Whips and Scorns of time,\n"                        \
    "The Oppressor's wrong, the proud man's Contumely,\n"                       \
    "The pangs of dispised Love, the Law’s delay,\n"                            \
    "The insolence of Office, and the spurns\n"                                 \
    "That patient merit of the unworthy takes,\n"                               \
    "When he himself might his Quietus make\n"                                  \
    "With a bare Bodkin? Who would Fardels bear, \n"                            \
    "To grunt and sweat under a weary life,\n"                                  \
    "But that the dread of something after death,\n"                            \
    "The undiscovered country, from whose bourn\n"                              \
    "No traveller returns, puzzles the will,\n"                                 \
    "And makes us rather bear those ills we have,\n"                            \
    "Than fly to others that we know not of.\n"                                 \
    "Thus conscience doth make cowards of us all,\n"                            \
    "And thus the native hue of Resolution\n"                                   \
    "Is sicklied o'er, with the pale cast of Thought,\n"                        \
    "And enterprises of great pitch and moment, \n"                             \
    "With this regard their Currents turn awry, \n"                             \
    "And lose the name of Action. Soft you now,\n"                              \
    "The fair Ophelia? Nymph, in thy Orisons\n"                                 \
    "Be all my sins remember'd.\n"

#define COSE_TEST_AAD                                                           \
"It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness, it was the spring of hope, it was the winter of despair, we had everything before us, we had nothing before us, we were all going direct to Heaven, we were all going direct the other way—in short, the period was so far like the present period, that some of its noisiest authorities insisted on its being received, for good or for evil, in the superlative degree of comparison only."

#endif
