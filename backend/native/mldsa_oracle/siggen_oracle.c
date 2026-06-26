#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mldsa_native.h>

static int hex_nibble(char value)
{
  if (value >= '0' && value <= '9')
  {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f')
  {
    return value - 'a' + 10;
  }
  if (value >= 'A' && value <= 'F')
  {
    return value - 'A' + 10;
  }
  return -1;
}

static int parse_hex(const char *name, const char *hex, uint8_t *out,
                     size_t expected_bytes)
{
  size_t hex_len = strlen(hex);
  size_t i;

  if (hex_len != expected_bytes * 2)
  {
    fprintf(stderr, "%s must be exactly %zu hex characters\n", name,
            expected_bytes * 2);
    return -1;
  }

  for (i = 0; i < expected_bytes; i++)
  {
    int high = hex_nibble(hex[i * 2]);
    int low = hex_nibble(hex[(i * 2) + 1]);

    if (high < 0 || low < 0)
    {
      fprintf(stderr, "%s contains non-hex characters\n", name);
      return -1;
    }

    out[i] = (uint8_t)((high << 4) | low);
  }

  return 0;
}

static int parse_hex_alloc(const char *name, const char *hex, uint8_t **out,
                           size_t *out_len)
{
  size_t hex_len = strlen(hex);
  size_t byte_len;
  size_t i;

  if (hex_len % 2 != 0)
  {
    fprintf(stderr, "%s hex string must have an even number of characters\n",
            name);
    return -1;
  }

  byte_len = hex_len / 2;
  *out = NULL;
  *out_len = byte_len;

  if (byte_len == 0)
  {
    return 0;
  }

  *out = (uint8_t *)malloc(byte_len);
  if (*out == NULL)
  {
    fprintf(stderr, "failed to allocate %s buffer\n", name);
    return -1;
  }

  for (i = 0; i < byte_len; i++)
  {
    int high = hex_nibble(hex[i * 2]);
    int low = hex_nibble(hex[(i * 2) + 1]);

    if (high < 0 || low < 0)
    {
      fprintf(stderr, "%s contains non-hex characters\n", name);
      free(*out);
      *out = NULL;
      *out_len = 0;
      return -1;
    }

    (*out)[i] = (uint8_t)((high << 4) | low);
  }

  return 0;
}

static int parse_binary_flag(const char *name, const char *value, int *out)
{
  if (strcmp(value, "0") == 0)
  {
    *out = 0;
    return 0;
  }
  if (strcmp(value, "1") == 0)
  {
    *out = 1;
    return 0;
  }
  fprintf(stderr, "%s must be 0 or 1\n", name);
  return -1;
}

static int parse_hash_alg(const char *value, int *hash_alg, size_t *hash_bytes)
{
  if (strcmp(value, "SHA2-224") == 0)
  {
    *hash_alg = MLD_PREHASH_SHA2_224;
    *hash_bytes = 28;
    return 0;
  }
  if (strcmp(value, "SHA2-256") == 0)
  {
    *hash_alg = MLD_PREHASH_SHA2_256;
    *hash_bytes = 32;
    return 0;
  }
  if (strcmp(value, "SHA2-384") == 0)
  {
    *hash_alg = MLD_PREHASH_SHA2_384;
    *hash_bytes = 48;
    return 0;
  }
  if (strcmp(value, "SHA2-512") == 0)
  {
    *hash_alg = MLD_PREHASH_SHA2_512;
    *hash_bytes = 64;
    return 0;
  }
  if (strcmp(value, "SHA2-512/224") == 0)
  {
    *hash_alg = MLD_PREHASH_SHA2_512_224;
    *hash_bytes = 28;
    return 0;
  }
  if (strcmp(value, "SHA2-512/256") == 0)
  {
    *hash_alg = MLD_PREHASH_SHA2_512_256;
    *hash_bytes = 32;
    return 0;
  }
  if (strcmp(value, "SHA3-224") == 0)
  {
    *hash_alg = MLD_PREHASH_SHA3_224;
    *hash_bytes = 28;
    return 0;
  }
  if (strcmp(value, "SHA3-256") == 0)
  {
    *hash_alg = MLD_PREHASH_SHA3_256;
    *hash_bytes = 32;
    return 0;
  }
  if (strcmp(value, "SHA3-384") == 0)
  {
    *hash_alg = MLD_PREHASH_SHA3_384;
    *hash_bytes = 48;
    return 0;
  }
  if (strcmp(value, "SHA3-512") == 0)
  {
    *hash_alg = MLD_PREHASH_SHA3_512;
    *hash_bytes = 64;
    return 0;
  }
  if (strcmp(value, "SHAKE-128") == 0)
  {
    *hash_alg = MLD_PREHASH_SHAKE_128;
    *hash_bytes = 32;
    return 0;
  }
  if (strcmp(value, "SHAKE-256") == 0)
  {
    *hash_alg = MLD_PREHASH_SHAKE_256;
    *hash_bytes = 64;
    return 0;
  }

  fprintf(stderr, "unsupported hashAlg: %s\n", value);
  return -1;
}

static int parse_context(const char *hex, uint8_t **context, size_t *context_len)
{
  if (parse_hex_alloc("context", hex, context, context_len) != 0)
  {
    return -1;
  }
  if (*context_len > 255)
  {
    fprintf(stderr, "context must be at most 255 bytes\n");
    free(*context);
    *context = NULL;
    *context_len = 0;
    return -1;
  }
  return 0;
}

static void print_hex_upper(const uint8_t *buffer, size_t length)
{
  static const char hex[] = "0123456789ABCDEF";
  size_t i;

  for (i = 0; i < length; i++)
  {
    fputc(hex[buffer[i] >> 4], stdout);
    fputc(hex[buffer[i] & 0x0F], stdout);
  }
}

int main(int argc, char **argv)
{
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sig[CRYPTO_BYTES];
  uint8_t rnd[MLDSA_RNDBYTES] = {0};
  uint8_t mu[MLDSA_CRHBYTES];
  uint8_t *message = NULL;
  const uint8_t *input = NULL;
  size_t input_len = 0;
  size_t siglen = 0;
  int externalmu = 0;
  int deterministic = 1;
  const char *sk_hex;
  const char *input_hex;
  const char *rnd_hex = NULL;
  int rc;

  if (argc >= 2 && strcmp(argv[1], "external") == 0)
  {
    uint8_t ph[64];
    uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];
    uint8_t *context = NULL;
    uint8_t *external_message = NULL;
    size_t context_len = 0;
    size_t external_message_len = 0;
    size_t ph_len = 0;
    size_t pre_len = 0;
    int hash_alg = MLD_PREHASH_NONE;
    const char *mode;

    if (argc < 7)
    {
      fprintf(stderr,
              "usage: %s external pure <deterministic> <sk_hex> "
              "<message_hex> <context_hex> [rnd_hex]\n"
              "   or: %s external preHash <deterministic> <sk_hex> "
              "<prehash_hex> <context_hex> <hashAlg> [rnd_hex]\n",
              argv[0], argv[0]);
      return 2;
    }

    mode = argv[2];
    if (parse_binary_flag("deterministic", argv[3], &deterministic) != 0)
    {
      return 2;
    }
    if (parse_hex("sk", argv[4], sk, sizeof(sk)) != 0)
    {
      return 2;
    }

    if (strcmp(mode, "pure") == 0)
    {
      if ((deterministic && argc != 7) || (!deterministic && argc != 8))
      {
        fprintf(stderr, "invalid external pure argument count\n");
        return 2;
      }
      if (parse_hex_alloc("message", argv[5], &external_message,
                          &external_message_len) != 0 ||
          parse_context(argv[6], &context, &context_len) != 0)
      {
        free(external_message);
        return 2;
      }
      pre_len = mldsa_prepare_domain_separation_prefix(
          pre, NULL, 0, context, context_len, MLD_PREHASH_NONE);
      if (pre_len == 0)
      {
        fprintf(stderr, "failed to prepare pure ML-DSA domain prefix\n");
        free(context);
        free(external_message);
        return 2;
      }
    }
    else if (strcmp(mode, "preHash") == 0)
    {
      if ((deterministic && argc != 8) || (!deterministic && argc != 9))
      {
        fprintf(stderr, "invalid external preHash argument count\n");
        return 2;
      }
      if (parse_hash_alg(argv[7], &hash_alg, &ph_len) != 0 ||
          parse_hex("prehash", argv[5], ph, ph_len) != 0 ||
          parse_context(argv[6], &context, &context_len) != 0)
      {
        free(context);
        return 2;
      }
    }
    else
    {
      fprintf(stderr, "external mode must be pure or preHash\n");
      return 2;
    }

    if (deterministic)
    {
      rnd_hex = NULL;
    }
    else
    {
      rnd_hex = (strcmp(mode, "pure") == 0) ? argv[7] : argv[8];
      if (parse_hex("rnd", rnd_hex, rnd, sizeof(rnd)) != 0)
      {
        free(context);
        free(external_message);
        return 2;
      }
    }

    if (strcmp(mode, "pure") == 0)
    {
      rc = mldsa_signature_internal(sig, &siglen, external_message,
                                    external_message_len, pre, pre_len, rnd,
                                    sk, 0);
    }
    else
    {
      rc = mldsa_signature_pre_hash_internal(sig, &siglen, ph, ph_len, context,
                                             context_len, rnd, sk, hash_alg);
    }

    free(context);
    free(external_message);

    if (rc != 0)
    {
      fprintf(stderr, "external signing failed: %d\n", rc);
      return 1;
    }
    if (siglen != sizeof(sig))
    {
      fprintf(stderr, "signature length mismatch: got %zu bytes, expected %zu\n",
              siglen, sizeof(sig));
      return 1;
    }

    fputs("{\"signature\":\"", stdout);
    print_hex_upper(sig, sizeof(sig));
    fputs("\"}\n", stdout);
    return 0;
  }

  if (argc == 3)
  {
    sk_hex = argv[1];
    input_hex = argv[2];
  }
  else if (argc == 5 || argc == 6)
  {
    if (parse_binary_flag("externalmu", argv[1], &externalmu) != 0 ||
        parse_binary_flag("deterministic", argv[2], &deterministic) != 0)
    {
      return 2;
    }

    if (deterministic && argc != 5)
    {
      fprintf(stderr, "rnd_hex is not allowed when deterministic=1\n");
      return 2;
    }
    if (!deterministic && argc != 6)
    {
      fprintf(stderr, "rnd_hex is required when deterministic=0\n");
      return 2;
    }

    sk_hex = argv[3];
    input_hex = argv[4];
    if (!deterministic)
    {
      rnd_hex = argv[5];
    }
  }
  else
  {
    fprintf(stderr,
            "usage: %s <sk_hex> <message_hex>\n"
            "   or: %s <externalmu> <deterministic> <sk_hex> "
            "<message_or_mu_hex> [rnd_hex]\n"
            "   or: %s external pure <deterministic> <sk_hex> "
            "<message_hex> <context_hex> [rnd_hex]\n"
            "   or: %s external preHash <deterministic> <sk_hex> "
            "<prehash_hex> <context_hex> <hashAlg> [rnd_hex]\n",
            argv[0], argv[0], argv[0], argv[0]);
    return 2;
  }

  if (parse_hex("sk", sk_hex, sk, sizeof(sk)) != 0)
  {
    return 2;
  }

  if (externalmu)
  {
    if (parse_hex("mu", input_hex, mu, sizeof(mu)) != 0)
    {
      return 2;
    }
    input = mu;
    input_len = sizeof(mu);
  }
  else
  {
    if (parse_hex_alloc("message", input_hex, &message, &input_len) != 0)
    {
      return 2;
    }
    input = message;
  }

  if (rnd_hex != NULL && parse_hex("rnd", rnd_hex, rnd, sizeof(rnd)) != 0)
  {
    free(message);
    return 2;
  }

  /*
   * ACVP internal sigGen targets FIPS 204 Algorithm 7 ML-DSA.Sign_internal.
   * externalmu=0 consumes the ACVP message. externalmu=1 consumes the ACVP mu.
   * The randomized Phase 2-5 path is controlled only by the provided rnd bytes.
   */
  rc = mldsa_signature_internal(sig, &siglen, input, input_len, NULL, 0, rnd, sk,
                                externalmu);
  free(message);

  if (rc != 0)
  {
    fprintf(stderr, "mldsa_signature_internal failed: %d\n", rc);
    return 1;
  }
  if (siglen != sizeof(sig))
  {
    fprintf(stderr, "signature length mismatch: got %zu bytes, expected %zu\n",
            siglen, sizeof(sig));
    return 1;
  }

  fputs("{\"signature\":\"", stdout);
  print_hex_upper(sig, sizeof(sig));
  fputs("\"}\n", stdout);

  return 0;
}
