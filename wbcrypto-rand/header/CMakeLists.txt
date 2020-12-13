option(INSTALL_WbcryptoRand_HEADERS "Install WbcryptoRand headers." ON)

if(INSTALL_WbcryptoRand_HEADERS)
    install(FILES WbcryptoRand/rand.h DESTINATION include/WbcryptoRand/)

endif(INSTALL_WbcryptoRand_HEADERS)
