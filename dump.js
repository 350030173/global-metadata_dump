//
//获取解密后的global-metadata.dat
//
//用法：
//frida -U -l global-metadata_dump.js packagename
//
//导出的文件在/data/data/yourPackageName/global-metadata.dat
//
//get_self_process_name()获取当前运行进程包名
//参考：https://github.com/lasting-yang/frida_dump/blob/master/dump_dex_class.js
//
//
function get_self_process_name() {
    var openPtr = Module.getExportByName('libc.so', 'open');
    var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

    var readPtr = Module.getExportByName("libc.so", "read");
    var read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);

    var closePtr = Module.getExportByName('libc.so', 'close');
    var close = new NativeFunction(closePtr, 'int', ['int']);

    var path = Memory.allocUtf8String("/proc/self/cmdline");
    var fd = open(path, 0);
    if (fd != -1) {
        var buffer = Memory.alloc(0x1000);

        var result = read(fd, buffer, 0x1000);
        close(fd);
        result = ptr(buffer).readCString();
        return result;
    }

    return "-1";
}


function frida_Memory(pattern)
{
	Java.perform(function ()
	{
		console.log("头部标识:" + pattern);
		//枚举内存段的属性,返回指定内存段属性地址
		var addrArray = Process.enumerateRanges("r--");
		for (var i = 0; i < addrArray.length; i++)
		{
			var addr = addrArray[i];
			Memory.scan(addr.base, addr.size, pattern,
			{
				onMatch: function (address, size)
				{
					console.log('搜索到 ' + pattern + " 地址是:" + address.toString());
					console.log(hexdump(address, 
					{
						offset: 0,
						length: 64,
						header: true,
						ansi: true
					}));
					//0x108，0x10C如果不行，换0x100，0x104
					var DefinitionsOffset = parseInt(address, 16) + 0x108;
					var DefinitionsOffset_size = Memory.readInt(ptr(DefinitionsOffset));
					
					var DefinitionsCount = parseInt(address, 16) + 0x10C;
					var DefinitionsCount_size = Memory.readInt(ptr(DefinitionsCount));
					
					//根据两个偏移得出global-metadata大小
					var global_metadata_size = DefinitionsOffset_size + DefinitionsCount_size
					console.log("大小：",global_metadata_size);
					var file = new File("/data/data/" + get_self_process_name() + "/global-metadata.dat", "wb");
					file.write(Memory.readByteArray(address, global_metadata_size));
					file.flush();
					file.close();
					console.log('导出完毕...');
				},
				onComplete: function ()
				{
					//console.log("搜索完毕")
				}
			}
			);
		}
	}
	);
}

setImmediate(frida_Memory("AF 1B B1 FA 18"));//global-metadata.dat头部特征
