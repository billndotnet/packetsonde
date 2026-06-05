#ifndef PS_RECIPE_AUTHORING_H
#define PS_RECIPE_AUTHORING_H
struct ps_args;
int ps_recipe_sign_main  (int argc, char **argv, const struct ps_args *opts);
int ps_recipe_verify_main(int argc, char **argv, const struct ps_args *opts);
int ps_recipe_info_main  (int argc, char **argv, const struct ps_args *opts);
#endif
