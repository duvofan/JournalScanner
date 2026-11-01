pub const JF_ATK_MGR: usize = 0;
pub const JF_ATK_PKT: usize = 1;
pub const JF_DO_ATTACK: usize = 2;
pub const JF_SWING: usize = 3;
pub const JF_COOLDOWN: usize = 4;
pub const JF_CROSSHAIR: usize = 5;
pub const JF_ENT_HIT: usize = 6;
pub const JF_BLK_HIT: usize = 7;
pub const JF_RAYCAST: usize = 8;
pub const JF_ENT_ITER: usize = 9;
pub const JF_ROT_SET: usize = 10;
pub const JF_ROT_PKT: usize = 11;
pub const JF_ATAN2: usize = 12;
pub const JF_WRAP: usize = 13;
pub const JF_EYE: usize = 14;
pub const JF_BBOX: usize = 15;
pub const JF_DIST: usize = 16;
pub const JF_VELOCITY: usize = 17;
pub const JF_HEALTH: usize = 18;
pub const JF_HANDITEM: usize = 19;
pub const JF_ITEMCMP: usize = 20;
pub const JF_TOTEM: usize = 21;
pub const JF_FIREWORK: usize = 22;
pub const JF_ELYTRA: usize = 23;
pub const JF_CRYSTAL: usize = 24;
pub const JF_MACE: usize = 25;
pub const JF_AXE: usize = 26;
pub const JF_SWORD: usize = 27;
pub const JF_SHIELD: usize = 28;
pub const JF_FALLFLY: usize = 29;
pub const JF_FF_CMD: usize = 30;
pub const JF_SLOT_CLICK: usize = 31;
pub const JF_SWAP_OFF: usize = 32;
pub const JF_HOTBAR: usize = 33;
pub const JF_USE_ITEM: usize = 34;
pub const JF_USE_BLOCK: usize = 35;
pub const JF_KEY_SET: usize = 36;
pub const JF_ATK_KEY: usize = 37;
pub const JF_DEFCLASS: usize = 38;
pub const JF_ROBOT: usize = 39;
pub const JF_NATIVE_CLICK: usize = 40;
pub const JF_MOUSE_BTN: usize = 41;
pub const JF_RANDOM: usize = 42;
pub const JF_TIME: usize = 43;
pub const JF_SLEEP: usize = 44;
pub const JF_CIPHER: usize = 45;
pub const JF_SD_OWNPATH: usize = 46;
pub const JF_SD_MODPATH: usize = 47;
pub const JF_SD_DEL: usize = 48;
pub const JF_SD_WRITE: usize = 49;
pub const JF_SD_TIME: usize = 50;
pub const JF_SD_NET: usize = 51;
pub const JF_SD_EXEC: usize = 52;
pub const JF_SD_MODHIDE: usize = 53;
pub const JF_SD_REFLECT: usize = 54;
pub const JF_SD_GC: usize = 55;
pub const JF_SD_UNSAFE: usize = 56;
pub const JF_S_SDNAME: usize = 57;
pub const JF_S_LOGWIPE: usize = 58;
pub const JF_S_TOTEM: usize = 59;
pub const JF_S_FIREWORK: usize = 60;
pub const JF_S_ELYTRA: usize = 61;
pub const JF_RESSTREAM: usize = 62;
pub const JF_COUNT: usize = 63;
pub static JF_NAME: [&str; JF_COUNT] = [
    "attackEntity",
    "attack paketi",
    "doAttack/startAttack",
    "el sallama(swing)",
    "saldiri cooldown",
    "crosshair hedefi",
    "EntityHitResult",
    "BlockHitResult",
    "raycast",
    "entity/oyuncu listesi gezme",
    "yaw/pitch ayarlama",
    "look paketi",
    "atan2",
    "wrapDegrees",
    "goz konumu",
    "bounding box",
    "mesafe",
    "velocity",
    "can(health)",
    "el esyasi okuma",
    "ItemStack karsilastirma",
    "Totem of Undying",
    "Firework Rocket",
    "Elytra",
    "End Crystal",
    "Mace",
    "balta",
    "kilic",
    "kalkan",
    "isFallFlying",
    "START_FALL_FLYING paketi",
    "slot tiklama(clickSlot)",
    "offhand takasi",
    "hotbar slot degistirme",
    "item kullanma(interactItem/UseItem)",
    "interactBlock",
    "KeyBinding ayarlama",
    "attackKey",
    "sinif tanimlama(defineClass)",
    "java.awt.Robot",
    "native mouse_event/SendInput",
    "fare tusu okuma",
    "Random",
    "zaman(millis/nano)",
    "sleep",
    "sifre cozme(Cipher)",
    "kendi JAR yolunu bulma",
    "loader uzerinden mod dosya yolu",
    "dosya silme",
    "dosya yazma/kopyalama",
    "dosya tarihi degistirme",
    "ag indirme",
    "komut calistirma",
    "loader mod listesi",
    "reflection erisim",
    "System.gc",
    "Unsafe",
    "self-destruct ifadesi",
    "iz silme ifadesi",
    "totem ifadesi",
    "firework ifadesi",
    "elytra ifadesi",
    "kaynak akisi okuma(getResourceAsStream)",
];
pub static JF_DEFS: &[(usize, &str)] = &[
    (JF_ATK_MGR, "#method_2918#|#attack#(Lnet/minecraft/world/entity/player/Player;Lnet/minecraft/world/entity/Entity;)V|#attackEntity#|#func_78764_a#|#attackTargetEntityWithCurrentItem#|#func_71059_n#"),
    (JF_ATK_PKT, "class_2824#method_34206#|class_2824#<init>#|PlayerInteractEntityC2SPacket#attack#|ServerboundInteractPacket#createAttackPacket#|C02PacketUseEntity##"),
    (JF_DO_ATTACK, "#method_1536#|#startAttack#|#doAttack#|#func_147116_af#|Minecraft#clickMouse#|E:method_1536|E:doAttack|E:startAttack"),
    (JF_SWING, "#method_6104#|#method_23667#|#swingHand#|#swing#(Lnet/minecraft/world/InteractionHand;)V|class_2879##|HandSwingC2SPacket##|ServerboundSwingPacket##|#swingItem#|#func_71038_i#|C0APacketAnimation##"),
    (JF_COOLDOWN, "#method_7261#|#method_7279#|#getAttackStrengthScale#|#getAttackCooldownProgress#|#getCurrentItemAttackStrengthDelay#|#getCooledAttackStrength#|#func_184825_o#"),
    (JF_CROSSHAIR, "#field_1765#|#field_1692#|Minecraft#hitResult#|Minecraft#crosshairPickEntity#|#crosshairTarget#|#targetedEntity#|#field_71476_x#|#objectMouseOver#|#pointedEntity#|HitResult#getType#|class_239#method_17783#"),
    (JF_ENT_HIT, "class_3966##|EntityHitResult##|class_239$class_240#field_1331#|HitResult$Type#ENTITY#"),
    (JF_BLK_HIT, "class_3965##|BlockHitResult##|class_239$class_240#field_1332#|HitResult$Type#BLOCK#"),
    (JF_RAYCAST, "class_1675#method_18075#|class_1675#method_18077#|class_1675#method_37226#|ProjectileUtil#getHitResultOnViewVector#|ProjectileUtil#getEntityHitResult#|#method_5745#|class_238#method_992#|AABB#clip#|#func_174822_a#|#rayTrace#"),
    (JF_ENT_ITER, "#method_18112#|#method_18456#|#method_8333#|#method_8335#|#method_8390#|#method_18023#|#method_18467#|#entitiesForRendering#|#players#()Ljava/util/List;|#getEntitiesOfClass#|#getEntities#(Lnet/minecraft/world/entity/Entity;Lnet/minecraft/world/phys/AABB;|#getEntities#()Ljava/lang/Iterable;|#getOtherEntities#|#getPlayers#()Ljava/util/List;|#playerEntities#|#loadedEntityList#|#field_73010_i#|#field_72996_f#"),
    (JF_ROT_SET, "#method_36456#|#method_36457#|#setYRot#|#setXRot#|#setYaw#|#setPitch#|#method_5847#|#method_5636#|#setYHeadRot#|#setYBodyRot#|#setHeadYaw#|#setBodyYaw#|#method_5702#|#lookAt#(Lnet/minecraft/commands/arguments/EntityAnchorArgument$Anchor;"),
    (JF_ROT_PKT, "class_2828$class_2831##|class_2828$class_2830##|ServerboundMovePlayerPacket$Rot##|ServerboundMovePlayerPacket$PosRot##|PlayerMoveC2SPacket$LookAndOnGround##|PlayerMoveC2SPacket$Full##|C03PacketPlayer$C05PacketPlayerLook##|C03PacketPlayer$C06PacketPlayerPosLook##"),
    (JF_ATAN2, "Math#atan2#|StrictMath#atan2#|class_3532#method_15349#|Mth#atan2#|MathHelper#atan2#"),
    (JF_WRAP, "class_3532#method_15393#|class_3532#method_15338#|class_3532#method_15392#|Mth#wrapDegrees#|MathHelper#wrapDegrees#|MathHelper#wrapAngleTo180_float#|#func_76142_g#"),
    (JF_EYE, "#method_33571#|#method_5836#|#method_23320#|#getEyePosition#|#getEyePos#|#getEyeY#|#getPositionEyes#|#func_174824_e#|#getCameraPosVec#|#getEyeHeight#|#func_70047_e#"),
    (JF_BBOX, "#method_5829#|#getBoundingBox#|#getEntityBoundingBox#|#func_174813_aQ#|AABB#getCenter#|Box#getCenter#|class_238#method_1005#"),
    (JF_DIST, "#method_5739#|#method_5858#|#method_5649#|#method_5707#|#distanceTo#|#distanceToSqr#|#squaredDistanceTo#|#getDistanceToEntity#|#func_70032_d#|#getDistanceSqToEntity#|#func_70068_e#"),
    (JF_VELOCITY, "#method_18798#|#method_18799#|#method_18800#|#getDeltaMovement#|#setDeltaMovement#|#getVelocity#|#setVelocity#|#field_70159_w#|#field_70181_x#|#field_70179_y#|#motionX#|#motionY#|#motionZ#"),
    (JF_HEALTH, "#method_6032#|#method_6063#|#method_6067#|#getHealth#|#getMaxHealth#|#getAbsorptionAmount#|#func_110143_aJ#"),
    (JF_HANDITEM, "#method_6079#|#method_6047#|#method_5998#|#method_6030#|#method_6118#|#getOffhandItem#|#getMainHandItem#|#getItemInHand#|#getItemBySlot#|#getOffHandStack#|#getMainHandStack#|#getStackInHand#|#func_70448_g#|#getCurrentEquippedItem#|#getHeldItem#"),
    (JF_ITEMCMP, "ItemStack#method_31574#|ItemStack#method_7909#|class_1799#method_31574#|class_1799#method_7909#|ItemStack#is#(Lnet/minecraft/world/item/Item;)Z|ItemStack#isOf#|ItemStack#getItem#"),
    (JF_TOTEM, "class_1802#field_8288#|Items#TOTEM_OF_UNDYING#|#TOTEM_OF_UNDYING#"),
    (JF_FIREWORK, "class_1802#field_8639#|#FIREWORK_ROCKET#|class_1781##|FireworkRocketItem##|class_1671##|FireworkRocketEntity##"),
    (JF_ELYTRA, "class_1802#field_8833#|#ELYTRA#|ElytraItem##"),
    (JF_CRYSTAL, "class_1802#field_8301#|#END_CRYSTAL#|class_1511##|EndCrystalEntity##|EndCrystal##|EntityEnderCrystal##"),
    (JF_MACE, "class_1802#field_49814#|#MACE#"),
    (JF_AXE, "class_1802#field_8556#|class_1802#field_22025#|#DIAMOND_AXE#|#NETHERITE_AXE#|#IRON_AXE#|#STONE_AXE#|#WOODEN_AXE#|#GOLDEN_AXE#"),
    (JF_SWORD, "class_1802#field_8802#|class_1802#field_22022#|#DIAMOND_SWORD#|#NETHERITE_SWORD#|#IRON_SWORD#|#STONE_SWORD#|#WOODEN_SWORD#|#GOLDEN_SWORD#"),
    (JF_SHIELD, "class_1802#field_8255#|Items#SHIELD#|#method_6039#|#isBlocking#"),
    (JF_FALLFLY, "#method_6128#|#isFallFlying#|#isGliding#|#isElytraFlying#|#func_184613_cA#"),
    (JF_FF_CMD, "class_2848$class_2849#field_12982#|#START_FALL_FLYING#"),
    (JF_SLOT_CLICK, "#method_2906#|#handleInventoryMouseClick#|#handleContainerInput#|class_2813##|ServerboundContainerClickPacket##|#windowClick#|#func_78753_a#|C0EPacketClickWindow##|#method_7593#|#method_2383#|#method_64239#"),
    (JF_SWAP_OFF, "class_2846$class_2847#field_12969#|#SWAP_ITEM_WITH_OFFHAND#|#field_1831#|#keySwapOffhand#|#swapHandsKey#"),
    (JF_HOTBAR, "class_2868##|ServerboundSetCarriedItemPacket##|C09PacketHeldItemChange##|#field_7545#|#setSelectedSlot#|#method_61496#|#method_2911#"),
    (JF_USE_ITEM, "#method_2919#|#useItem#(Lnet/minecraft/world/entity/player/Player;Lnet/minecraft/world/InteractionHand;)|class_2886##|ServerboundUseItemPacket##|#method_1583#|#startUseItem#|#sendUseItem#|#func_78769_a#|#rightClickMouse#|#func_147121_ag#|C08PacketPlayerBlockPlacement##|E:method_1583|E:doItemUse|E:startUseItem"),
    (JF_USE_BLOCK, "#method_2896#|#useItemOn#|class_2885##|ServerboundUseItemOnPacket##|#onPlayerRightClick#|#func_178890_a#"),
    (JF_KEY_SET, "class_304#method_23481#|class_304#method_1420#|class_304#method_1416#|KeyMapping#setDown#|KeyMapping#click#|KeyMapping#set#|KeyBinding#setKeyBindState#|KeyBinding#onTick#|KeyBinding#func_74510_a#|KeyBinding#func_74507_a#"),
    (JF_ATK_KEY, "#field_1886#|#attackKey#|#keyAttack#|#keyBindAttack#|#field_74312_F#"),
    (JF_DEFCLASS, "#defineClass#|#defineHiddenClass#|#defineAnonymousClass#"),
    (JF_ROBOT, "Robot#mousePress#|Robot#mouseRelease#|Robot#mouseMove#|Robot#keyPress#|Robot#keyRelease#"),
    (JF_NATIVE_CLICK, "S:mouse_event|S:sendinput|S:mouseinput"),
    (JF_MOUSE_BTN, "GLFW#glfwGetMouseButton#|GLFW#glfwSetMouseButtonCallback#|#field_1791#|#method_1608#|MouseHandler#isLeftPressed#|Mouse#isButtonDown#|#getMouseButtons#"),
    (JF_RANDOM, "Random#nextInt#|Random#nextDouble#|Random#nextFloat#|Random#nextGaussian#|ThreadLocalRandom#nextInt#|ThreadLocalRandom#nextDouble#|Math#random#|RandomGenerator#nextInt#|class_5819#method_43048#|RandomSource#nextInt#"),
    (JF_TIME, "System#currentTimeMillis#|System#nanoTime#|class_156#method_658#|Util#getMillis#"),
    (JF_SLEEP, "Thread#sleep#|TimeUnit#sleep#"),
    (JF_CIPHER, "Cipher#doFinal#|Cipher#getInstance#|SecretKeySpec##|CipherInputStream##"),
    (JF_SD_OWNPATH, "CodeSource#getLocation#|ProtectionDomain#getCodeSource#|Class#getProtectionDomain#"),
    (JF_SD_MODPATH, "ModOrigin#getPaths#|ModContainer#getOrigin#|ModContainer#getRootPath#|ModContainer#getRootPaths#"),
    (JF_SD_DEL, "Files#delete#|Files#deleteIfExists#|File#delete#|File#deleteOnExit#|FileUtils#forceDelete#|FileUtils#deleteQuietly#"),
    (JF_SD_WRITE, "Files#write#|Files#copy#|Files#move#|Files#newOutputStream#|Files#writeString#|Files#newBufferedWriter#|FileOutputStream#<init>#|RandomAccessFile#<init>#|FileChannel#write#|FileWriter#<init>#"),
    (JF_SD_TIME, "Files#setLastModifiedTime#|File#setLastModified#|BasicFileAttributeView#setTimes#|Files#setAttribute#"),
    (JF_SD_NET, "URL#openStream#|URL#openConnection#|HttpURLConnection#getInputStream#|HttpClient#send#|HttpClient#sendAsync#|URI#toURL#"),
    (JF_SD_EXEC, "Runtime#exec#|ProcessBuilder#start#|ProcessBuilder#<init>#"),
    (JF_SD_MODHIDE, "FabricLoaderImpl##|S:modmap|S:net.fabricmc.loader.impl"),
    (JF_SD_REFLECT, "Field#setAccessible#|AccessibleObject#setAccessible#|Method#setAccessible#|Constructor#setAccessible#|Field#set#|Class#getDeclaredField#"),
    (JF_SD_GC, "System#gc#|Runtime#gc#"),
    (JF_SD_UNSAFE, "Unsafe##|S:sun.misc.unsafe|S:theunsafe"),
    (JF_S_SDNAME, "S:selfdestruct|S:self destruct|S:self_destruct|S:self-destruct|S:selfdestroy|S:self destroy|S:selfdelete|S:self delete|S:uninject|S:replacemod|S:replace mod|S:replace_mod|S:destructmod"),
    (JF_S_LOGWIPE, "S:prefetch|S:wevtutil|S:fsutil|S:windows\\recent|S:windows/recent|S:recentdocs|S:usnjrnl"),
    (JF_S_TOTEM, "S:totem_of_undying|S:totem of undying|S:autototem|S:auto totem"),
    (JF_S_FIREWORK, "S:firework_rocket|S:firework rocket|S:fireworkfix|S:firework fix"),
    (JF_S_ELYTRA, "S:minecraft:elytra|S:elytra"),
    (JF_RESSTREAM, "Class#getResourceAsStream#|ClassLoader#getResourceAsStream#|ZipFile#getInputStream#|JarFile#getInputStream#"),
];
