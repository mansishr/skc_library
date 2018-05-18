#ifndef _KEYAGENT_
#define _KEYAGENT_


#ifdef  __cplusplus
extern "C" {
#endif

gboolean key_agent_init(const char *filename, GError **err);
void key_agent_listnpms();
void key_agent_liststms();

#ifdef  __cplusplus
}
#endif

#endif
