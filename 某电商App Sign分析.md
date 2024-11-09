# 电商App Sign分析

**观前提示：**

**本文章仅供学习交流,切勿用于非法通途,如有侵犯贵司请及时联系删除**



```
样本：jingdong-10.2.0

```

# 0x1 抓包&定位

打开样本App 直接抓包

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3bBfMlJvhUAzaTdO6kErwVWXPI2JicTYayS8mZsicxMtGZXrekbrLYlGQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

本次的受害参数为`sign`

打开jadx定位到`sign`的加密位置

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3Y9oFkcNkicr8z5CneibZE07B5V5QbibErnKAlohJfUkUNhzuiaCCKiced9w/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

加载的so为`libjdbitmapkit.so`

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD37dTxsP0PMxHxiaY4KicppX4Xoa3RKYBJ3UyN5ciaX3W0DIocqfqosyC6Q/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

有了这些信息 上frida hook入参和结果

打开frida 启动样本App发现 App卡死闪退

可能有frida检测 那我们就使用葫芦娃大佬的魔改frida

> github: https://github.com/hluwa/strongR-frida-android

继续启动frida 发现还是崩溃

猜测可能还有其他检测方式

根据网上文章给出的frida检测点进行多次尝试

经过多次试错后最后可知 样本App对frida的默认端口`27042`进行检测

那就需要让frida运行在非默认端口

```
/data/local/tmp/hluda-server-15.1.17-android-arm64 -l 127.0.0.1:8080
```

然后映射端口

```
adb forward tcp:8080 tcp:8080
```

最后启动frida

```
frida -H 127.0.0.1:8080
```

成功运行frida且不闪退后就可以对样本进行hook操作了

```
function hook_getSignFromJni() {
    Java.perform(function () {
        var Class = Java.use('com.xxxx.common.utils.BitmapkitUtils');
        var Method = "getSignFromJni"
        Class[Method].overload('android.content.Context', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function () {
            var result = this[Method]['apply'](this, arguments);
            console.log('----------------------');
            console.log('arg1:' + arguments[0]);
            console.log('arg2:' + arguments[1]);
            console.log('arg2:' + arguments[2]);
            console.log('arg2:' + arguments[3]);
            console.log('arg2:' + arguments[4]);
            console.log('arg2:' + arguments[5]);
            console.log('result:' + result);
            console.log('----------------------');
            return result;
        }
    })
}
setImmediate(hook_getSignFromJni)
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD359ibag6U8bBPCDIrZ9qyDjfeiaozS9j1bMWBj1wiaib3A3XicdAX2EUgdiaw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

通过hook 拿到了多个结果 选取其中一个进行固定分析

```
arg1:com.jingdong.app.mall.JDApp@f0dac2f
arg2:hotWords
arg2:{"originHotWord":"0","pageFrom":"1"}
arg2:3036c83c3c4b25a2
arg2:android
arg2:10.2.0
result:st=1664463515894&sign=7ce2045026643e68ea1639c5e291127f&sv=122
```

# 0x2 Unidbg黑盒调用

复制粘贴造个轮子运行

根据报错信息开始补环境

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3hibraibTE7s4pPt37uJ4yP7q8yZyfnia2myu3n6PibgyQl7iambpY336ptg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

```
vm.resolveClass("android/app/Activity");
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3Ul2LjgqnYRp60YXugu2LWUs4HjibaZXkqYPPibgXicTDTOquHPIf3IQFQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)取`getpackagemanager`所以需要在前面的基础上再完善一点环境

```
vm.resolveClass("android/app/Activity",vm.resolveClass("android/content/ContextWrapper", vm.resolveClass("android/content/Context"))).newObject(null);
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD37NcfIqKno0njqj51ErjzsuIQar6PAFpfaC3amQadld4bjEXib1fU1Qg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)取`ApplicationInfo`也就是apk的存放位置 可以在RE文件管理器`/data/app`中找到对应的位置

```
new StringObject(vm,"/data/app/com.xxxx.app.mall-cd4VeJ0b5yxrR0Zb-io_MA=/base.apk");
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3aSVwhVTuibIRgGMd6gS5ypDu6piclDsRBG5XCORic9NEvWMEY3ajriaqpw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)取`unZip` 看传入参数是什么![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3ibrdvdP4xyKq4SlRfITtDM1kw1aBgNlg0abn1BHP3u5fIMlzAyt21SA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)传入了仨参数

```
arg1->"/data/app/com.xxxx.app.mall-cd4VeJ0b5yxrR0Zb-io_MA=/base.apk"
arg2->"META-INF/"
arg3->".RSA"
```

根据参数打开APK中中的`META-INF`搜索`RSA`结尾的文件![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3ZcckOJCHKYQibkUg9iarJNr4PiaGGlnsx7qKXe54q6Pg8kCVsKPdxnibsw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)根据这个文件名补即可

```
new ByteArray(vm,vm.unzip("META-INF/xxxx.RSA"));
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3Xh3Hc3AlIxDY5iaQdibkWNhs1dtXibfEoGgnAkUAAx3Qp51xEqKgBPBGg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

```
vm.resolveClass("sun/security/pkcs/PKCS7").newObject(new PKCS7((byte[]) varArg.getObjectArg(0).getValue()));
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3Gb1MEVPzMo3W1rm7ft5FNnGW0jUmdYiahYl9DFngpAgPUSicMPUtpqrw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

```
PKCS7 pkcs7 = (PKCS7) dvmObject.getValue();  
X509Certificate[] certificates = pkcs7.getCertificates();  
return ProxyDvmObject.createObject(vm,certificates);
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3caOYia5NqKwuxhvnTElTtzb3iaVY3FwjOT5FHyF3F4TfaDZUQxcYK9ug/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)这里的`objectToBytes`是java层的一个方法 直接去复制粘贴就行

```
new ByteArray(vm,objectToBytes(varArg.getObjectArg(0).getValue()));
```

补到这里 恭喜你完成初始化了![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD32Qr5qicEEgDPaPOcib0GyjWkry9bUqI8NI4iamzib2NgRicoHPewpauzhwA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

主动调用`getSignFromJni`

```
public void getSignFromJni(){
    ArrayList<Object> args = new ArrayList<>(10);
    args.add(vm.getJNIEnv());
    args.add(0);
    args.add(vm.addLocalObject(vm.resolveClass("android/content/Context").newObject(null)));
    args.add(vm.addLocalObject(new StringObject(vm,"hotWords")));
    args.add(vm.addLocalObject(new StringObject(vm,"{\"originHotWord\":\"0\",\"pageFrom\":\"1\"}")));
    args.add(vm.addLocalObject(new StringObject(vm,"3036c83c3c4b25a2")));
    args.add(vm.addLocalObject(new StringObject(vm,"android")));
    args.add(vm.addLocalObject(new StringObject(vm,"10.2.0")));
    Number number = module.callFunction(emulator, 0x28b5, args.toArray());
    System.out.println(vm.getObject(number.intValue()).getValue().toString());
}
```

然后接着报错接着补环境![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3cCvGHAXbf8IFOwFBzfwwFHicWrMPkXpwb7g9Hl3eWj5flpFL0QY15jQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

```
vm.resolveClass("java/lang/StringBuffer").newObject(new StringBuffer());
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3tt0LTZY6ZOdPcPlWw7yDSZbGI9MX8MonsWNK70Qib2upkiaj8jALE5AQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

```
StringBuffer stringBuffer = (StringBuffer) dvmObject.getValue();
return vm.resolveClass("java/lang/StringBuffer").newObject(stringBuffer.append(vaList.getObjectArg(0).getValue()));
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3eeRKKrDwY2HTTMV11lpar7cjQAmOldh8WHBicGftny5rPEiacAA8dulQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

```
Integer integer = new Integer(vaList.getIntArg(0));  
return vm.resolveClass("java/lang/Integer").newObject(integer);
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3ia7pvHa7Fk6drncavqroiblyN97EPSqFxA8gdLZdNvaEgyn3opJ8dZ4Q/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

```
Integer integer = (Integer) dvmObject.getValue();  
return vm.resolveClass("java/lang/Integer").newObject(integer.toString());
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3n6Y6dia9eJJ0QJfWAhztgrSoiaHS0Y00RKBH2y40nzIBer6QvMZ6DMeA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

```
StringBuffer stringBuffer = (StringBuffer) dvmObject.getValue();
return new StringObject(vm,stringBuffer.toString());
```

恭喜你 补到这里就能出结果了

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD31DWxmZcqsBpo6vuXicjQZGfZFUesvQpXfC5MibyoSvuPpibpAsWOMzcDQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

小声bb 写到这里就1k字了还没开始看算法

多次调用sv变动 st变动 sign也变动

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3QhicfXicWg3Gcwp6UVia9YS20e74oYhI8qFSoYIxo7y6vRZtIOmoHQ2Bg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

# 0x3 算法分析

IDA打开直接搜索

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3iarJHXaXiaqc6ViaOT2klGYlUX157z2c6CA9JKokB5aXbmCVMKbLPO0JQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

看到直接是静态注册的

双击跳转过去

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3By0734A48deykD5HibicIFicWAUNHyl8SEiazibwCFr0plNbHwq6QPs7tbA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

这一段全是拼接操作

`st`生成位置![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3eq8hZyoqAvywow9ia9jMjEO6uLia43l1xicftZnQg3zJYhV0Ok4nzS2zA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)`sv`生成位置![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3jxtVO1ick4w97n0XoZbVvPjo5icux1WLia1kh213ia2vyhaTeb31hLUq3g/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

**固定随机项**

idea双击shift搜`gettimeofday`

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3yuqNg6RFHRKOuicevE6C4jicLD3pTF8bSU8AicfeFjVKibrya4hboibjkxA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)改为固定的时间戳![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD369n9AV1icOHCqaSvxmt8puRjodbAnxaibhaaMrtV6HO8nBCgeN7pQQ6w/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)固定了时间 不同的sv算出来的sign结果也不一致![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3icvwAun04M8UrNibF53hjpqWDPicnBYX6hsP0mRXdvo6nCdLU0o27MVQg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)观察代码 sv是通过`lrand48`生成的

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3TTYN2kvn2vutxnQKDY9N20WmbCs9aJJTriaGTzaluU8YbUiaXric5bic4A/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

固定`lrand48`

```
HookZz instance = HookZz.getInstance(emulator);
instance.wrap(module.findSymbolByName("lrand48"), new WrapCallback<HookZzArm32RegisterContext>() {
    int count=0;
    @Override
    public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
    }
    @Override
    public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
        count+=1;
        if(count==2){
            ctx.setR0(0x1);
        }
        if(count==1){
            ctx.setR0(0x1);
        }
    }
});
```

就是这俩处位置结果变动使`sign`的结果随之改变

改了这些就可以为所欲为了![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3a2Blbj7X1QMDoLVa9I3mibanEjhWUn4VJQfZUgldtngpLPQjtTw5asw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

前面拼接了一堆东西的结果传入`sub_126AC`![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3AvaJfpxphHiaIZPtiaPQKSMRaTCjF1xcJeic5BeBE1L8jjEmQKQCddCQA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)先放着继续往下看

`sub_126AC`传回的结果放入了`sub_18B8`![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3tM2qIPEOdVofoTfeIAbSibEox0jPq3IEbBbX2weiawcsOhF0seGLWc7Q/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)进入`sub_18B8`![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD347AWhCicI2iavvibRPx5C9TfKNHKEQrS2UqgdprESLNCtuClb6q0jIL3w/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)看到这里似乎是一个Base64的码表![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3AykXsLIbx77ljibxgzVNOEEmfSicbBdeicAujA207mWJufkhGb0hJicmicQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)那`sub_18B8`可能就是一个Base64方法

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3T7JKRvNvuMibFU7bKDoSyCrNucc64FLcBOeIPncAiariavvfNSUoicL6Ow/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

```
sub_18B8`的结果由v66传出并且传入`sub_227C
```

进入`sub_227C`

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3VniarJKbjsyCyZRicJVakvFIr8x2ic9WMZYPboYmWfKO5n77SAEImkSag/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

看到似曾相识的东西 这样看可能不是很明显 手动分割一下

- 0xEFCDAB89
- 0x67452301
- 0x10325476
- 0x98BADCFE

这不就是MD5

从魔数上看 似乎并没有魔改

验证一下前面的Base64和MD5猜想

拿到`sub_126AC`的结果进行Base64再MD5

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3lZqkcupajkicoHicraE5DaZImWF87dtgSVeV3ynAcgKL2VdwhJYgdjuw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

验证成功 那重心就在`sub_126AC`了

回到`sub_126AC`

这里有3个case分别代表三个算法

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3c2aQyU1k67hgqOsOtFQHicic1IftGPKg3lyMiahKlgYrOao5TCtFqiaqkg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

而算法的走向是由v24决定

v24是由sv2和sv3决定的

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3gBFOCAzTqSScGk2pGvj9LXZzcnZLKXC52cIszAfy0ljrqOwSODGicibg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

根据伪代码逻辑可以翻译为

```
unk_17440 = [0, 1, 2]
sv1 = 1
sv2 = 1
sv3 = 1
print(unk_17440[(sv2 + sv3) % 3])
```

根据结果得到下表

| sv1  | sv2  | sv3  |  sv  | case |
| :--: | :--: | :--: | :--: | :--: |
|  1   |  0   |  0   | 100  |  0   |
|  1   |  0   |  1   | 101  |  1   |
|  1   |  0   |  2   | 102  |  2   |
|  1   |  1   |  0   | 110  |  1   |
|  1   |  1   |  1   | 111  |  2   |
|  1   |  1   |  2   | 112  |  0   |
|  1   |  2   |  0   | 120  |  2   |
|  1   |  2   |  1   | 121  |  0   |
|  1   |  2   |  2   | 122  |  1   |

往下看这里先是内存拷贝了一个值然后根据v12 * 40的值进行偏移 其实实现的就是一个数组取值的操作![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3Osoxia3r3sdoflNic7LFMkp6EQCRFoxZAFlvq7wiaia2SQjp5xUwFyib2eQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)这里根据伪代码可以翻译为

```
v11 = ['44e715a6e322ccb7d028f7a42fa55040', '7d0069660c9b5d32074facf37c3738a1', '80306f4370b39fd5630ad0529f77adb6']
v13 = v11[v12]
```

接下来的重点就是在

- case 1->sub_10E18
- case 2->sub_10DE4
- case 0->sub_10E4C

前面手动固定了`lrand48` sv为111

所以走的是case 2

进入`sub_10DE4` 只有三个方法

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3Kag0orsIIyM8V4mbZ1ViaL92qEQNWzY9m9CxlicvPkC686ibtHibfMHkiaQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

算法在`sub_12ECC`中 双击进来

根据hook入参得到以下结果

```
a2->80306f4370b39fd5630ad0529f77adb6
a3->0x1
a4->functionId=hotWords&body={"originHotWord":"0","pageFrom":"1"}&uuid=3036c83c3c4b25a2&client=android&clientVersion=10.2.0&st=1664689004670&sv=111
a5->0x8f
```

由入参可知a4为拼接后的明文 a5是a4的长度

所以这个if是必定成立的 else后面的那一块可以忽略不看![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3mNKBlobrhu34BbGdJo3cn8qzLjGOdgQOb0rjtL0Hkkaq1AG3tErkjA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

这一段主要在计算v21![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3FlLszfeSyA95nyCibFibuXUw73pqudFPT4lQVrxCo0yg5XpM9owprZMg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

这里的a3对应的是sv1 而sv1固定为1 所以同理 不用理else部分![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3nuuLIPic4BrpibxCtC0uO9My4tPBPWoicHzc1ibhtcemtDouHUPStgynLA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

这里就是`sub_12ECC`的核心计算位置![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3Oktbm9kicaerYYMFaYWAR0yEaGQFkjWxpV8iaAHWR8Cd3g4IiaiaibxRMwQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

其中

```
v16 = &v21[7] + (v15 & 0xF);
v18 =*(v16 - 20);
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3MNJp3PX4ZpHLqBicLicJIXLSGMGZ8YreUcUd8ibhOf35MR2HjLliaC36ng/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)从汇编中可知`R0=(SP+0x20-0x14)+(R3&0xf)`

所以这段实现的操作是`v21[v15&0xf]`

v21结果为`SP+0xC`

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3zohTibibdIHS55Rr7dhIUiaHYFbuH5X2sbDclpOkXjR1fFLyk9aMK65Ng/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

也就是前面小端结果![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3TicCRbGTBUvPxiaF6LBgK684qgUvolSJxALUPpWdtn6GxKKgv7QJ3R5w/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)往下看

```
v17 = v15++ & 7;
result = ((v18 ^ *a4 ^ *(a2 + v17)) + v18);
```

此处为取值进行异或操作

```
LOBYTE(v18) = v18 ^ result;
*a4++ = v18;
*(a4 - 1) = v18 ^ *(a2 + v17);
```

将异或后的结果取低位然后再与`a2[v17]`进行运算最后算出结果

整个循环翻译成py简简单单没有难点

```
v15 = 0
v21 = [0x37, 0x92, 0x44, 0x68, 0xA5, 0x3D, 0xCC, 0x7F, 0xBB, 0x0F, 0xD9, 0x88, 0xEE, 0x9A, 0xE9, 0x5A]
while v15 != a5:
    v18 = v21[v15 % 16]
    v17 = v15 & 7
    result = (v18 ^ a4[v15] ^ a2[v17]) + v18
    v18 = v18 ^ result % 256
    a4[v15] = v18 ^ a2[v17]
    v15 += 1
```

运算后的结果Base64再MD5即为sign值![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3IRZOfkFMgibg0ntw0KI2M3EcYYaqb3EiclAV56SzvHFPo65nyY3OQr6Q/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

这是简单的`case 2`

接下来将前面固定`lrand48`的返回值改为`0x2` 使得sv为122

当sv为122时 走`case 1`

进入`sub_10E18` 和前面一样进来就是三个方法

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3UbdVG7Ov7AFvfp1vlG9dPABFQATblrJIoor3UM6VmiaBpDz8sicn5T4g/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

但是不同的是出现了一个`nullsub_1` 那就分析不了吗？

并不然 从前面的分析结合这里可知 `sub_125F0`可能为初始化 `sub_12510`可能为计算核心方法 那`nullsub_1`就可能是释放 所以并不需要理睬`nullsub_1`

进入`sub_12510`

入参和前面基本一致 a2变为`7d0069660c9b5d32074facf37c3738a1`

这里循环每次取8个字节进入`sub_10EA4`计算 一共循环`a5 >> 3`次![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3t4ibruibEtY5on97nENjueRPSYCIuUDCtItYYoUJyN3KHPpxeIAKQiavg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

进入`sub_10EA4` 955行代码 有点多 不过大部分都能直接复制

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3qD8zEchG2AOu6SSe1zcmgbEGREujB8pkBnHC6GL88tkqZiaAEPbE5WQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

这里一堆与操作的目的就是将传入的8位分别和`0x80 0x40 0x20 0x10 8 4 2 1`与操作扩展至64位![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3MABS1WodbuOicJKcK76xrN3AVb5TjKuV1O6ORLukn44va3mCOQZ0r3Q/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

接着就是一堆赋值 直接Ctrl+C Ctrl+V

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3aldL08OEqFfDbXXTxmCDxCFWyjf730Pu7HThRht607ibz75iaibOR07tw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

这里为遍历`a2`然后进行判断走不同分支![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3Z6yTJM1WANDar2peg5vHXTn31ouxSErHvlURuvBibKvuQoTibkmAmkuw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

其中出现了一些goto操作![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3BicOXaZnNHE5l8uwiae3S2rSfmImAdXFmfdlMN7uJMwQW75Z27EflXqQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

Python本身是没有的 但是可以依靠一个库`goto-statement`来实现

```
pip install goto-statement
```

> https://www.w3cschool.cn/article/3069641.html

这里就是将前面计算好并且重新赋值后的64位循环4次计算 每次取16位![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3dTYrhJJOFPdg4fHIX1RiakKibYwCjic83RWtRJM9VTrtWK9XDvYumd67w/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

每次循环更改2位 循环4次一共8位

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD32WDUJBiajB6OTFGia1ZMeu8ia9VT06ZXbLa7ib4TU4ZWicT149jdC8dIhdA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

实现了goto 其他操作只需要复制粘贴复制粘贴并稍微改改就能实现 反正全靠肝

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3fVQH17icwMSohjS7d6wGz6ZDibyfZ75Tg8HXj74JxZbbAdGt1uo93tVQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

回到上层 这里一共循环`0x8f >> 3 = 17` 但是似乎还有部分明文并没有参与计算 而最后得出的结果显示 全部都参与了计算

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3bibcK0Cp6HuIzibMnkLFcToZ6VfE0TJXYCpBy7kQVWdtmDdBTGkMC9xg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

hook验证猜想

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD392svibW1KWu0bsEmWLaic0kVH2ruwYCw4yEf41F5tWfyysUmGJMB5V3A/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

确实 只循环了17次 后面还会有`&sv=122`没有参与计算 但是从最终结果来看 确实是计算到了 那是哪里计算了呢？

直接`traceWrite`

```
emulator.traceWrite(0x4021c080L,0x4021c080L+10L);
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3PZs2ANK9NSE5FfeNVRQWibE1ZIc4araaqedeopxHCsOTLrspiaL6C3mw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)跳转`0xfbd0`

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3le0WibucHLvY6uBY9ZN0WRQj5eKiahnNT673dExH3iaBBMar1HDQjuF0w/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)这里就是赋值位置 但是 这里居然有3509行 这谁顶得住

先不管 看一下`sub_E7FC`的交叉引用

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3DTMSpy3yIXLz9KDy5p0bAW00TPjHCpdEY7ibhz4frQ72CYSHyibRTxeQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

只一个 跳转过来

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD338vUHfa0eTMAxTUgRmOOicWzyr64a0mfoFfBHicSumGDu8cprEIJ3sPQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

从`(a4 & 7) - 1`可知

这。。这段不就是根据未参与计算的明文的长度走不同的方法 而且每个方法都有上千行 留给有肝的人还原吧

将之前还原好的做个验证没问题
![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3PQsorbBvPthSy7uUwGqmEESUI9zKCCYhbPI6iaCqG9ibWEwy0OGy3B1g/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

接下来将前面固定`lrand48`的返回值改为`0x0` 使得sv为100

当sv为100时 走`case 0`

进入`sub_10E4C` 一样的三个方法

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3GCHvFC7D0iakGAVvdGoH6ffWRxXO2wKl10JWER3JvHFzMWzDUnpgqiaw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

进入`sub_12580` 看到核心方法是一样的`sub_10EA4` 不过16变成了32

![图片](https://mmbiz.qpic.cn/mmbiz_png/Em7AaVMQYsMmKnbNgDPsLwsm4lA51vD3csUkPEaZoEDn2sJD0icjibACgxbLPVwsV7lUWI7uV5ZHbibwAjfvkFtvg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

其余的和前面分析case2的一致

到此整一个流程就基本走完了 最后再拼接成`st=xxx&sign=xxx&sv=xxx`即可