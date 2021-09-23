'use strict';


let fs = require('fs');

const { ensureDir, nodes, makeHeader, sanitize, year } = require('../lib/utilities.js');

const outDir = 'out/';
const pathDir = 'path/';
ensureDir(outDir + pathDir);


function cap(name) {
  return name[0].toUpperCase() + name.slice(1);
}

let branchContent = `${makeHeader(__filename)}

package com.shapesecurity.shift.es${year}.astpath;


import com.shapesecurity.functional.data.Maybe;
import com.shapesecurity.shift.es${year}.ast.*;

import java.util.Objects;


public abstract class ASTPath<S, T> extends ObjectPath<S, T> {
  private ASTPath() {}

  public abstract String propertyName();

  private static abstract class TrivialPath<S, T> extends ObjectPath<S, T> {
    public boolean equals(Object o) {
      return this == o || o != null && getClass() == o.getClass();
    }

    public int hashCode() {
      return Objects.hash(getClass());
    }
  }

  private static abstract class IndexedPath<S, T> extends ObjectPath<S, T> {
    final int index;

    protected IndexedPath(int index) {
      this.index = index;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      IndexedPath<?, ?> that = (IndexedPath<?, ?>) o;
      return index == that.index;
    }

    @Override
    public int hashCode() {
      return Objects.hash(getClass(), index);
    }
  }

`;

let classContent = [];
let classes = [];

// console.log(require('util').inspect(spec, { depth: Infinity }));
// return;

for (let typeName of Array.from(nodes.keys()).sort()) {
  let type = nodes.get(typeName);
  if (type.children.length !== 0) continue;

  let attrs = type.attributes;

  attrs.forEach(a => {
    let isList = a.type.kind === 'list';
    let isMaybe = a.type.kind === 'nullable';// || a.type.kind === 'list' && a.type.argument.kind === 'nullable';
    let isListMaybe = a.type.kind === 'list' && a.type.argument.kind === 'nullable';

    let name = `${typeName}_${cap(a.name)}`;
    if (isList) {
      classContent.push(`
  public static ${name} ${name}(${isList ? 'int index' : ''}) {
    return new ${name}(${isList ? 'index' : ''});
  }
`);
    } else {
      classContent.push(`
  public static final ${name} ${name} = new ${name}();
`)
    }

    let returnType = isListMaybe
      ? a.type.argument.argument.argument
      : isList || isMaybe
        ? a.type.argument.argument
        : a.type.argument;

    // capitalize first letter, for primitives
    returnType = returnType[0].toUpperCase() + returnType.substring(1);

    // enums need to be qualified, for some reason
    if (a.type.kind === 'enum' && returnType.endsWith('Operator')) {
      returnType = `com.shapesecurity.shift.es${year}.ast.operators.${returnType}`;
    }

    let superClass = isListMaybe || isList ? 'IndexedPath' : 'TrivialPath';
    let cl = `
  public static class ${name} extends ASTPath.${superClass}<${typeName}, ${returnType}> `;
    if (isListMaybe) {
      cl += `{
  protected ${name}(int index) {
      super(index);
    }

    @Override
    Maybe<${returnType}> apply(Object source) {
      if (!(source instanceof ${typeName})) return Maybe.empty();
      return ((${typeName}) source).${sanitize(a.name)}.index(index).orJust(Maybe.empty());
    }

    public String propertyName() {
      return "${a.name}[" + index + "]";
    }
  }`;
    } else if (isList) {
      cl += `{
    protected ${name}(int index) {
      super(index);
    }

    @Override
    Maybe<${returnType}> apply(Object source) {
      if (!(source instanceof ${typeName})) return Maybe.empty();
      return ((${typeName}) source).${sanitize(a.name)}.index(index);
    }

    public String propertyName() {
      return "${a.name}[" + index + "]";
    }
  }`;
    } else if (isMaybe) {
      cl += `{
    @Override
    Maybe<${returnType}> apply(Object source) {
      if (!(source instanceof ${typeName})) return Maybe.empty();
      return ((${typeName}) source).${sanitize(a.name)};
    }

    public String propertyName() {
      return "${a.name}";
    }
  }`;
    } else {
      cl += `{
    @Override
    Maybe<${returnType}> apply(Object source) {
      if (!(source instanceof ${typeName})) return Maybe.empty();
      return Maybe.of(((${typeName}) source).${sanitize(a.name)});
    }

    public String propertyName() {
      return "${a.name}";
    }
  }`;
    }

    classes.push(cl);
  });
}

branchContent += `${classContent.join('')}

${classes.join('\n')}
}
`;

fs.writeFileSync(outDir + pathDir + 'ASTPath.java', branchContent, 'utf-8');
