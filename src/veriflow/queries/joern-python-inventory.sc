@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)
  val represented = cpg.file.name.l.filter(_.endsWith(".py")).distinct.sorted
  val symbols = cpg.method
    .filterNot(m => Set("<module>", "<global>").contains(m.name))
    .filter(_.file.name.headOption.exists(_.endsWith(".py")))
    .l.map { m =>
    ujson.Obj(
      "file" -> m.file.name.headOption.getOrElse(""),
      "name" -> m.fullName,
      "simple_name" -> m.name,
      "line" -> m.lineNumber.getOrElse(-1),
      "end_line" -> m.lineNumberEnd.getOrElse(m.lineNumber.getOrElse(-1)),
      "kind" -> "function",
      "async" -> false
    )
  }
  val calls = cpg.call
    .filter(_.file.name.headOption.exists(_.endsWith(".py")))
    .l.map { c =>
    ujson.Obj(
      "file" -> c.file.name.headOption.getOrElse(""),
      "caller" -> c.method.name,
      "expression" -> c.name,
      "code" -> c.code,
      "line" -> c.lineNumber.getOrElse(-1),
      "end_line" -> c.lineNumber.getOrElse(-1),
      "resolution" -> (if (c.methodFullName.startsWith("<unknown>")) "unresolved" else "graph")
    )
  }
  val result = ujson.Obj(
    "schema_version" -> "1",
    "engine_id" -> "joern",
    "language" -> "python",
    "represented_files" -> ujson.Arr.from(represented),
    "symbols" -> ujson.Arr.from(symbols),
    "calls" -> ujson.Arr.from(calls)
  )
  java.nio.file.Files.writeString(java.nio.file.Path.of(outFile), ujson.write(result, indent = 2))
}
