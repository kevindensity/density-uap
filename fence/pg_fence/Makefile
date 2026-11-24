MODULE_big = pg_fence
OBJS = pg_fence.o
EXTENSION = pg_fence
DATA = pg_fence--0.1.sql
SHLIB_LINK = -lsodium
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
