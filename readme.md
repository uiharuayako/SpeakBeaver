# SpeakBeaver 语音大河狸

## 项目已迁移到Dalamud平台，请使用Dalamud以获得更好的语音输入体验

Dalamud版[SpeakBeaver](https://github.com/uiharuayako/SpeakBeaverDalamud)  

# ACT+鲶鱼精联动版 (仍可使用，如果因为版本更新触发器失效，请提issue)

这是一个让FF14支持语音输入的程序。

下载地址：[GitHub](https://github.com/uiharuayako/SpeakBeaver/releases/latest)、[蓝奏云](https://wwhp.lanzout.com/iBCuw0prjpna)

## 配置方式

1. 下载并解压 ``SpeakBeaver.zip``，确保 ``ff14yy.exe``和 ``xivyy.ini``在同一个文件夹
2. 进入[讯飞开放平台](https://www.xfyun.cn/)，申请一个开发者账号
3. 进入控制台，点击创建新应用，随便写一点内容。再次进入控制台，进入你创建的应用，在左边的菜单里找到 **语音听写（流式版）** 。这个东西每天都有500次的免费识别次数，真的用不完。如果你实在担心用完或者想和很多很多亲友分享，设置个支付密码就可以白嫖50000的服务量。
4. 在右边找到“服务接口认证信息”，把APPID、APISecret、APIKey的一串代码复制到 ``xivyy.ini``里，填到相应的等号后面（原文件文本中，*在“xxx”注册后领取* 这几个字需要删掉）
5. 在act中加载鲶鱼精邮差插件，下载地址：[GitHub](https://github.com/Natsukage/PostNamazu)、介绍页面：[NGA](https://ngabbs.com/read.php?tid=19724323)，勾选自动启动，设置端口后，点击启动，把设置的端口也填到 ``xivyy.ini`` 里
6. 在ini中填写单次最长输入时间，单位秒，默认15秒，使用act的限时输入时，会忽略ini中的默认设置
7. 填好鲶鱼精端口以及讯飞语音识别的几个信息后，打开 ``ff14yy.exe``，开启后可以最小化该窗口。
8. 在Act的TriggerNometry（高级触发器）里导入 ``语音输入.xml``，并依照触发器中的指示在游戏内设置宏
9. 在游戏里写一个宏 ``/e 发起语音输入请求喵``，按下宏，看到聊天栏中出现提示**开始语音输入**即可说话。一直说话会一直识别，5-6秒不说话后，识别自动停止，自动停止几秒之后，聊天栏会中出现提示**结束语音输入**，表示语音识别结束。（注意！在聊天栏出现提示之后，语音输入才会开始，不是按下宏后立刻开始）

## 另一种配置方式？

可以注意到，压缩包里还有一个 ``ff14yy_audio.exe``，当 ``xivyy.ini``被正确配置后，这个程序开启时就会自动连接，并进行语音识别，在识别结束后关闭。因此可以搭配VoiceBot，AVPI等语音识别程序，用语音控制语音识别。实现说出一个关键词，游戏就自动开始语音识别的效果。

但是在我个人的使用过程中，这一方式体验并不好。
