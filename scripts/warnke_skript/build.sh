./scripts/warnke_skript/format.sh && ./waf.sh configure --debug --sanitize  && ./waf.sh clean && ./waf.sh build && ./waf.sh install
#export ASAN_OPTIONS=fast_unwind_on_malloc=0
#export G_DEBUG=resident-modules
#export G_MESSAGES_DEBUG=all
