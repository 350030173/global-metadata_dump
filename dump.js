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
					
					var DefinitionsOffset = parseInt(address, 16) + 0x108;
					var DefinitionsOffset_size = Memory.readInt(ptr(DefinitionsOffset));
					
					var DefinitionsCount = parseInt(address, 16) + 0x10C;
					var DefinitionsCount_size = Memory.readInt(ptr(DefinitionsCount));
					
					//根据两个偏移得出global-metadata大小
					var global_metadata_size = DefinitionsOffset_size + DefinitionsCount_size
					console.log("global-metadata size：",global_metadata_size);
					var file = new File("/data/data/你的包名/global-metadata.dat", "wb");
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
