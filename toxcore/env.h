#ifndef OPSYS_H
#define OPSYS_H

typedef int Socket;

typedef struct Env {
  void (*closesocket)(Socket sock);
} Env;

Env *opsys_new(void);
void opsys_free(Env *env);

#endif /* OPSYS_H */
