from zipfile import ZipFile

if __name__ == "__main__":
	print("Order of commands is: method level-size zip-depth character")
	commands = input()
	commands = commands.split(" ")

	# as of right now the method does not matter
	for p in range(int(commands[2])):
		zipobj = ZipFile(f"lib-{p}.zip", "w")
		for n in range(int(commands[1])):
			filename = f"{commands[3]}-{n}.txt"
			with open(filename, "w") as file:
				for i in range(1000000):
					file.write(commands[3])

			zipobj.write(filename)
