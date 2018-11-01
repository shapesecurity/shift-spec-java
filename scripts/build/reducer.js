/**
 * Copyright 2016 Shape Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

let fs = require('fs');

const { ensureDir, nodes, makeHeader, isStatefulType, sanitize, toJavaType } = require('../lib/utilities.js');

const cloneReturnTypes = require('../lib/find-max-super').default(nodes);

const outDir = 'out/';
const reducerDir = 'reducer/';
const serializerDir = 'serialization/';
const rangeCheckerDir = 'parser/';
ensureDir(outDir + reducerDir);
ensureDir(outDir + serializerDir);
ensureDir(outDir + rangeCheckerDir);



let reducerContent = `${makeHeader(__filename)}

package com.shapesecurity.shift.es2016.reducer;

import com.shapesecurity.functional.data.ImmutableList;
import com.shapesecurity.functional.data.Maybe;
import com.shapesecurity.shift.es2016.ast.*;

import javax.annotation.Nonnull;

public interface Reducer<State> {`;

for (let typeName of Array.from(nodes.keys()).sort()) {
  let type = nodes.get(typeName);
  if (type.children.length !== 0) continue;

  let attrs = type.attributes.filter(f => isStatefulType(f.type)).map(f => `            @Nonnull ${toJavaType(f.type, 'State')} ${sanitize(f.name)}`);
  if (attrs.length === 0) {
    reducerContent += `
    @Nonnull
    State reduce${typeName}(@Nonnull ${typeName} node`;
  } else {
    reducerContent += `
    @Nonnull
    State reduce${typeName}(
            @Nonnull ${typeName} node,
${attrs.join(',\n')}`;
  }
  reducerContent += ');\n';
}

reducerContent += '}\n';

fs.writeFileSync(outDir + reducerDir + 'Reducer.java', reducerContent, 'utf-8');


let thunkedReducerContent = `${makeHeader(__filename)}

package com.shapesecurity.shift.es2016.reducer;

import com.shapesecurity.functional.data.ImmutableList;
import com.shapesecurity.functional.data.Maybe;
import com.shapesecurity.shift.es2016.ast.*;

import javax.annotation.Nonnull;
import java.util.function.Supplier;

public interface ThunkedReducer<State> {`;


function thunkName(type) {
  switch (type.kind) {
    case 'nullable':
      return `Maybe<${thunkName(type.argument)}>`;
    case 'list':
      return `ImmutableList<${thunkName(type.argument)}>`;
    case 'namedType':
    case 'union':
      throw 'Not reached'; // eliminated by unions-to-interfaces
    default:
      return 'Supplier<State>';
  }
}

for (let typeName of Array.from(nodes.keys()).sort()) {
  let type = nodes.get(typeName);
  if (type.children.length !== 0) continue;

  let attrs = type.attributes.filter(f => isStatefulType(f.type)).map(f => `            @Nonnull ${thunkName(f.type)} ${sanitize(f.name)}`);
  if (attrs.length === 0) {
    thunkedReducerContent += `
    @Nonnull
    State reduce${typeName}(@Nonnull ${typeName} node`;
  } else {
    thunkedReducerContent += `
    @Nonnull
    State reduce${typeName}(
            @Nonnull ${typeName} node,
${attrs.join(',\n')}`;
  }
  thunkedReducerContent += ');\n';
}

thunkedReducerContent += '}\n';

fs.writeFileSync(outDir + reducerDir + 'ThunkedReducer.java', thunkedReducerContent, 'utf-8');


let monoidalContent = `${makeHeader(__filename)}

package com.shapesecurity.shift.es2016.reducer;

import com.shapesecurity.functional.data.*;
import com.shapesecurity.shift.es2016.ast.*;

import javax.annotation.Nonnull;

public class MonoidalReducer<State> implements Reducer<State> {
    @Nonnull
    protected final Monoid<State> monoidClass;

    public MonoidalReducer(@Nonnull Monoid<State> monoidClass) {
        this.monoidClass = monoidClass;
    }

    protected State identity() {
        return this.monoidClass.identity();
    }

    protected State append(State a, State b) {
        return this.monoidClass.append(a, b);
    }

    protected State append(State a, State b, State c) {
        return append(append(a, b), c);
    }

    protected State append(State a, State b, State c, State d) {
        return append(append(a, b, c), d);
    }

    protected State fold(ImmutableList<State> as) {
        return as.foldLeft(this::append, this.identity());
    }

    protected State fold1(ImmutableList<State> as, State a) {
        return as.foldLeft(this::append, a);
    }

    @Nonnull
    protected State o(@Nonnull Maybe<State> s) {
        return s.orJust(this.identity());
    }
`;


function red(attr) {
  switch (attr.type.kind) {
    case 'nullable':
      return `o(${sanitize(attr.name)})`;
    case 'list':
      if (attr.type.argument.kind === 'nullable') {
        return `fold(Maybe.catMaybes(${sanitize(attr.name)}))`;
      }
      return `fold(${sanitize(attr.name)})`;
    default:
      return sanitize(attr.name);
  }
}

for (let typeName of Array.from(nodes.keys()).sort()) {
  let type = nodes.get(typeName);
  if (type.children.length !== 0) continue;

  let attrs = type.attributes.filter(f => isStatefulType(f.type));
  let attrStrings = attrs.map(f => `            @Nonnull ${toJavaType(f.type, 'State')} ${sanitize(f.name)}`);
  if (attrStrings.length === 0) {
    monoidalContent += `
    @Nonnull
    @Override
    public State reduce${typeName}(@Nonnull ${typeName} node`;
  } else {
    monoidalContent += `
    @Nonnull
    @Override
    public State reduce${typeName}(
            @Nonnull ${typeName} node,
${attrStrings.join(',\n')}`;
  }
  let rv;
  if (attrs.length === 0) {
    rv = 'this.identity()';
  } else if (attrs.length === 1) {
    rv = red(attrs[0]);
  } else if (attrs.length === 2 && attrs[1].type.kind === 'list' && attrs[0].type.kind !== 'list') {
    rv = `fold1(${sanitize(attrs[1].name)}, ${red(attrs[0])})`;
  } else {
    rv = `append(${attrs.map(red).join(', ')})`;
  }
  monoidalContent += `) {
        return ${rv};
    }
`;
}

monoidalContent += '}\n';

fs.writeFileSync(outDir + reducerDir + 'MonoidalReducer.java', monoidalContent, 'utf-8');


let cloneContent = `${makeHeader(__filename)}

package com.shapesecurity.shift.es2016.reducer;

import com.shapesecurity.functional.data.ImmutableList;
import com.shapesecurity.functional.data.Maybe;
import com.shapesecurity.shift.es2016.ast.*;
import javax.annotation.Nonnull;

public class ReconstructingReducer implements Reducer<Node> {`;


function cloneAttribute(attr) {
  if (!isStatefulType(attr.type)) {
    return `node.${sanitize(attr.name)}`;
  }
  switch (attr.type.kind) {
    case 'nullable':
      if (attr.type.argument.kind === 'list') {
        return `${sanitize(attr.name)}.map(x -> x.map(y -> (${attr.type.argument.argument.argument}) y))`;
      }
      return `${sanitize(attr.name)}.map(x -> (${attr.type.argument.argument}) x)`;

    case 'list':
      if (attr.type.argument.kind === 'nullable') {
        return `${sanitize(attr.name)}.map(x -> x.map(y -> (${attr.type.argument.argument.argument}) y))`;
      }
      return `${sanitize(attr.name)}.map(x -> (${attr.type.argument.argument}) x)`;

    case 'node':
      return `(${attr.type.argument}) ${sanitize(attr.name)}`;
    default:
      throw 'Not reached';
  }
}

for (let typeName of Array.from(nodes.keys()).sort()) {
  let type = nodes.get(typeName);
  if (type.children.length !== 0) continue;

  let attrs = type.attributes.filter(f => isStatefulType(f.type));
  let attrStrings = attrs.map(f => `            @Nonnull ${toJavaType(f.type, 'Node')} ${sanitize(f.name)}`);
  if (attrStrings.length === 0) {
    cloneContent += `
    @Nonnull
    @Override
    public ${cloneReturnTypes.get(typeName)} reduce${typeName}(@Nonnull ${typeName} node`;
  } else {
    cloneContent += `
    @Nonnull
    @Override
    public ${cloneReturnTypes.get(typeName)} reduce${typeName}(
            @Nonnull ${typeName} node,
${attrStrings.join(',\n')}`;
  }
  cloneContent += `) {
        return new ${typeName}(${type.attributes.map(cloneAttribute).join(', ')});
    }
`;
}

cloneContent += '}\n';

fs.writeFileSync(outDir + reducerDir + 'ReconstructingReducer.java', cloneContent, 'utf-8');


let serializerContent = `${makeHeader(__filename)}

package com.shapesecurity.shift.serialization;

import com.shapesecurity.functional.data.ImmutableList;
import com.shapesecurity.functional.data.Maybe;
import com.shapesecurity.functional.data.NonEmptyImmutableList;
import com.shapesecurity.shift.es2016.ast.*;
import com.shapesecurity.shift.es2016.ast.operators.BinaryOperator;
import com.shapesecurity.shift.es2016.ast.operators.CompoundAssignmentOperator;
import com.shapesecurity.shift.es2016.ast.operators.UnaryOperator;
import com.shapesecurity.shift.es2016.ast.operators.UpdateOperator;
import com.shapesecurity.shift.utils.Utils;
import com.shapesecurity.shift.es2016.reducer.Director;
import com.shapesecurity.shift.es2016.reducer.Reducer;

import javax.annotation.Nonnull;


public class Serializer implements Reducer<StringBuilder> {

    public static final Serializer INSTANCE = new Serializer();

    protected Serializer() {}

    public static String serialize(@Nonnull Program program) {
        return Director.reduceProgram(INSTANCE, program).toString();
    }

    @Nonnull
    private static JsonObjectBuilder b(@Nonnull String type) {
        return new JsonObjectBuilder().add("type", type);
    }

    @Nonnull
    private static StringBuilder list(@Nonnull ImmutableList<StringBuilder> values) {
        if (values.isEmpty()) {
            return new StringBuilder("[]");
        }
        StringBuilder sb = new StringBuilder("[");
        NonEmptyImmutableList<StringBuilder> nel = (NonEmptyImmutableList<StringBuilder>) values;
        sb.append(nel.head);
        nel.tail().foreach(s -> sb.append(",").append(s));
        sb.append("]");
        return sb;
    }

    @Nonnull
    private static StringBuilder o(@Nonnull Maybe<StringBuilder> el) {
        return el.orJust(new StringBuilder("null"));
    }

    private static class JsonObjectBuilder {
        final StringBuilder text = new StringBuilder("{");
        boolean first = true;

        @Nonnull
        JsonObjectBuilder add(@Nonnull String property, boolean value) {
            optionalComma();
            this.text.append(Utils.escapeStringLiteral(property)).append(":").append(value);
            return this;
        }

        @Nonnull
        JsonObjectBuilder add(@Nonnull String property, @Nonnull String value) {
            optionalComma();
            this.text.append(Utils.escapeStringLiteral(property)).append(":").append(Utils.escapeStringLiteral(value));
            return this;
        }

        @Nonnull
        JsonObjectBuilder add(@Nonnull String property, @Nonnull Number value) {
            optionalComma();
            this.text.append(Utils.escapeStringLiteral(property)).append(":").append(value);
            return this;
        }

        @Nonnull
        JsonObjectBuilder add(@Nonnull String property, @Nonnull BinaryOperator value) {
            optionalComma();
            this.text.append(Utils.escapeStringLiteral(property)).append(":").append(Utils.escapeStringLiteral(value.getName()));
            return this;
        }

        @Nonnull
        JsonObjectBuilder add(@Nonnull String property, @Nonnull CompoundAssignmentOperator value) {
            optionalComma();
            this.text.append(Utils.escapeStringLiteral(property)).append(":").append(Utils.escapeStringLiteral(value.getName()));
            return this;
        }

        @Nonnull
        JsonObjectBuilder add(@Nonnull String property, @Nonnull UnaryOperator value) {
            optionalComma();
            this.text.append(Utils.escapeStringLiteral(property)).append(":").append(Utils.escapeStringLiteral(value.getName()));
            return this;
        }

        @Nonnull
        JsonObjectBuilder add(@Nonnull String property, @Nonnull UpdateOperator value) {
            optionalComma();
            this.text.append(Utils.escapeStringLiteral(property)).append(":").append(Utils.escapeStringLiteral(value.getName()));
            return this;
        }

        @Nonnull
        JsonObjectBuilder add(@Nonnull String property, @Nonnull VariableDeclarationKind value) {
            optionalComma();
            this.text.append(Utils.escapeStringLiteral(property)).append(":").append(Utils.escapeStringLiteral(value.name));
            return this;
        }

        @Nonnull
        JsonObjectBuilder add(@Nonnull String property, @Nonnull StringBuilder value) {
            optionalComma();
            this.text.append(Utils.escapeStringLiteral(property)).append(":").append(value);
            return this;
        }

        @Nonnull
        JsonObjectBuilder addMaybeString(@Nonnull String property, @Nonnull Maybe<String> value) {
            optionalComma();
            this.text.append(Utils.escapeStringLiteral(property)).append(":").append(value.map(Utils::escapeStringLiteral).orJust("null"));
            return this;
        }

        @Nonnull
        JsonObjectBuilder add(@Nonnull String property, @Nonnull Maybe<StringBuilder> value) {
            optionalComma();
            this.text.append(Utils.escapeStringLiteral(property)).append(":").append(o(value));
            return this;
        }

        @Nonnull
        JsonObjectBuilder add(@Nonnull String property, @Nonnull ImmutableList<StringBuilder> value) {
            optionalComma();
            this.text.append(Utils.escapeStringLiteral(property)).append(":").append(list(value));
            return this;
        }

        @Nonnull
        JsonObjectBuilder addListMaybe(@Nonnull String property, @Nonnull ImmutableList<Maybe<StringBuilder>> value) { // because type erasure
            optionalComma();
            this.text.append(Utils.escapeStringLiteral(property)).append(":").append(list(value.map(Serializer::o)));
            return this;
        }

        @Nonnull
        StringBuilder done() {
            this.text.append("}");
            return this.text;
        }

        private void optionalComma() {
            if (this.first) {
                this.first = false;
            } else {
                this.text.append(",");
            }
        }
    }
`;

function whichAdd(type) {
  if (type.kind === 'list' && type.argument.kind === 'nullable') {
    return 'addListMaybe';
  } else if (type.kind === 'nullable' && type.argument.kind === 'value' && type.argument.argument === 'string') {
    return 'addMaybeString';
  }
  return 'add';
}

for (let typeName of Array.from(nodes.keys()).sort()) {
  let type = nodes.get(typeName);
  if (type.children.length !== 0) continue;

  serializerContent += `
    @Nonnull
    @Override
    public StringBuilder reduce${typeName}(@Nonnull ${typeName} node`;

  let attrStrings = type.attributes.filter(f => isStatefulType(f.type)).map(f => `, @Nonnull ${toJavaType(f.type, 'StringBuilder')} ${sanitize(f.name)}`);

  serializerContent += attrStrings.join('');

  serializerContent += `) {
        return b("${typeName}")${type.attributes.map(a => `.${whichAdd(a.type)}("${a.name}", ${isStatefulType(a.type) ? sanitize(a.name) : `node.${a.name}`})`).join('')}.done();
    }
`;
}

serializerContent += '}';

fs.writeFileSync(outDir + serializerDir + 'Serializer.java', serializerContent, 'utf-8');


let deserializerContent = `${makeHeader(__filename)}

package com.shapesecurity.shift.serialization;

import com.google.gson.*;

import com.shapesecurity.functional.data.ImmutableList;
import com.shapesecurity.functional.data.Maybe;
import com.shapesecurity.shift.es2016.ast.*;
import com.shapesecurity.shift.es2016.ast.operators.BinaryOperator;
import com.shapesecurity.shift.es2016.ast.operators.CompoundAssignmentOperator;
import com.shapesecurity.shift.es2016.ast.operators.UnaryOperator;
import com.shapesecurity.shift.es2016.ast.operators.UpdateOperator;

import org.json.JSONException;

import java.util.ArrayList;

public class Deserializer {

    protected Deserializer() {}

    public static Node deserialize(String toDeserialize) throws JSONException, IllegalAccessException, InstantiationException, ClassNotFoundException, NoSuchMethodException {
        JsonElement json = new JsonParser().parse(toDeserialize);
        return deserializeNode(json);
    }

    private static BinaryOperator deserializeBinaryOperator(JsonElement jsonElement) {
        String operatorString = jsonElement.getAsString();
        switch (operatorString) {
            case ",":
                return BinaryOperator.Sequence;
            case "||":
                return BinaryOperator.LogicalOr;
            case "&&":
                return BinaryOperator.LogicalAnd;
            case "|":
                return BinaryOperator.BitwiseOr;
            case "^":
                return BinaryOperator.BitwiseXor;
            case "&":
                return BinaryOperator.LogicalAnd;
            case "+":
                return BinaryOperator.Plus;
            case "-":
                return BinaryOperator.Minus;
            case "==":
                return BinaryOperator.Equal;
            case "!=":
                return BinaryOperator.NotEqual;
            case "===":
                return BinaryOperator.StrictEqual;
            case "!==":
                return BinaryOperator.StrictNotEqual;
            case "*":
                return BinaryOperator.Mul;
            case "/":
                return BinaryOperator.Div;
            case "%":
                return BinaryOperator.Rem;
            case "<":
                return BinaryOperator.LessThan;
            case "<=":
                return BinaryOperator.LessThanEqual;
            case ">":
                return BinaryOperator.GreaterThan;
            case ">=":
                return BinaryOperator.GreaterThanEqual;
            case "in":
                return BinaryOperator.In;
            case "instanceof":
                return BinaryOperator.Instanceof;
            case "<<":
                return BinaryOperator.Left;
            case ">>":
                return BinaryOperator.Right;
            case ">>>":
                return BinaryOperator.UnsignedRight;
            default:
                return null; // should not get here
        }
    }

    private static CompoundAssignmentOperator deserializeCompoundAssignmentOperator(JsonElement jsonElement) {
        String operatorString = jsonElement.getAsString();
        switch (operatorString) {
            case "+=":
                return CompoundAssignmentOperator.AssignPlus;
            case "-=":
                return CompoundAssignmentOperator.AssignMinus;
            case "*=":
                return CompoundAssignmentOperator.AssignMul;
            case "/=":
                return CompoundAssignmentOperator.AssignDiv;
            case "%=":
                return CompoundAssignmentOperator.AssignRem;
            case "<<=":
                return CompoundAssignmentOperator.AssignLeftShift;
            case ">>=":
                return CompoundAssignmentOperator.AssignRightShift;
            case ">>>=":
                return CompoundAssignmentOperator.AssignUnsignedRightShift;
            case "|=":
                return CompoundAssignmentOperator.AssignBitOr;
            case "^=":
                return CompoundAssignmentOperator.AssignBitXor;
            case "&=":
                return CompoundAssignmentOperator.AssignBitAnd;
            default:
                return null; // should not get here
        }
    }

    private static UnaryOperator deserializeUnaryOperator(JsonElement jsonElement) {
        String operatorString = jsonElement.getAsString();
        switch (operatorString) {
            case "+":
                return UnaryOperator.Plus;
            case "-":
                return UnaryOperator.Minus;
            case "!":
                return UnaryOperator.LogicalNot;
            case "~":
                return UnaryOperator.BitNot;
            case "typeof":
                return UnaryOperator.Typeof;
            case "void":
                return UnaryOperator.Void;
            case "delete":
                return UnaryOperator.Delete;
            default:
                return null;
        }
    }

    private static UpdateOperator deserializeUpdateOperator(JsonElement jsonElement) {
        String operatorString = jsonElement.getAsString();
        switch (operatorString) {
            case "++":
                return UpdateOperator.Increment;
            case "--":
                return UpdateOperator.Decrement;
            default:
                return null;
        }
    }

    private static VariableDeclarationKind deserializeVariableDeclarationKind(JsonElement jsonElement) {
        String kindString = jsonElement.getAsString();
        switch (kindString) {
            case "var":
                return VariableDeclarationKind.Var;
            case "const":
                return VariableDeclarationKind.Const;
            case "let":
                return VariableDeclarationKind.Let;
            default:
                return null;
        }
    }
`;

let innerDeserializerContent = `
    private static Node deserializeNode(JsonElement jsonElement) throws ClassNotFoundException, IllegalAccessException, InstantiationException, NoSuchMethodException {
        if (jsonElement.isJsonObject()) {
            JsonObject jsonObject = jsonElement.getAsJsonObject();
            if (jsonObject.has("type")) {
                String nodeType = jsonObject.get("type").getAsString();
                switch (nodeType) {
`;

let deserializers = new Map;

function makeDeserializer(type) { // todo consider generics
  let name, base;
  switch (type.kind) {
    case 'list':
      switch (type.argument.kind) {
        case 'nullable':
          if (type.argument.argument.kind !== 'node') break;
          name = `deserializeListMaybe${type.argument.argument.argument}`;
          if (deserializers.has(name)) return name;
          base = type.argument.argument.argument;
          deserializers.set(name, `
    private static ${toJavaType(type)} ${name}(JsonElement jsonElement) throws ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException {
        JsonArray jsonArray = jsonElement.getAsJsonArray();
        if (jsonArray.size() == 0) {
          return ImmutableList.nil();
        } else {
            ArrayList<Maybe<${base}>> deserializedElements = new ArrayList<>();
            for (JsonElement ele : jsonArray) {
                if (ele.isJsonNull()) {
                    deserializedElements.add(Maybe.nothing());
                } else {
                    deserializedElements.add(Maybe.just((${base}) deserializeNode(ele)));
                }
            }
            return ImmutableList.from(deserializedElements);
        }
    }
`);
          return name;
        case 'node':
          name = `deserializeList${type.argument.argument}`;
          if (deserializers.has(name)) return name;
          base = type.argument.argument;
          deserializers.set(name, `
    private static ${toJavaType(type)} ${name}(JsonElement jsonElement) throws ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException {
        JsonArray jsonArray = jsonElement.getAsJsonArray();
        if (jsonArray.size() == 0) {
          return ImmutableList.nil();
        } else {
            ArrayList<${base}> deserializedElements = new ArrayList<>();
            for (JsonElement ele : jsonArray) {
                ${base} deserializedElement = (${base}) deserializeNode(ele);
                deserializedElements.add(deserializedElement);
            }
            return ImmutableList.from(deserializedElements);
        }
    }
`);
          return name;
      }
      break;
    case 'nullable':
      switch (type.argument.kind) {
        case 'node':
          name = `deserializeMaybe${type.argument.argument}`;
          if (deserializers.has(name)) return name;
          base = type.argument.argument;
          deserializers.set(name, `
    private static ${toJavaType(type)} ${name}(JsonElement jsonElement) throws ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException {
        if (jsonElement.isJsonNull()) {
            return Maybe.nothing();
        }
        return Maybe.just((${base}) deserializeNode(jsonElement));
    }
`);
          return name;
        case 'value':
          base = toJavaType(type.argument);
          name = `deserializeMaybe${base}`;
          if (deserializers.has(name)) return name;
          deserializers.set(name, `
    private static ${toJavaType(type)} ${name}(JsonElement jsonElement) {
        if (jsonElement.isJsonNull()) {
            return Maybe.nothing();
        } else {
            return Maybe.just(jsonElement.getAsString());
        }
    }
`);
          return name;
      }
      break;
  }
  throw 'Unhandled type ' + JSON.stringify(type);
}

// todo consider checking if attributes failed to get created

function deserializer(attr) {
  switch (attr.type.kind) {
    case 'list':
    case 'nullable':
      return `${makeDeserializer(attr.type)}(jsonObject.get("${attr.name}"))`;
    case 'value':
      switch (attr.type.argument) {
        case 'string':
          return `jsonObject.get("${attr.name}").getAsString()`;
        case 'boolean':
          return `jsonObject.get("${attr.name}").getAsBoolean()`;
        case 'double':
          return `jsonObject.get("${attr.name}").getAsDouble()`;
        default:
          throw new Error('unreachable');
      }
    case 'node':
      return `(${attr.type.argument}) deserializeNode(jsonObject.get("${attr.name}"))`;
    case 'enum':
      return `deserialize${attr.type.argument}(jsonObject.get("${attr.name}"))`;
  }
  throw 'Unhandled type ' + JSON.stringify(attr.type);
}

for (let typeName of Array.from(nodes.keys()).sort()) {
  let type = nodes.get(typeName);
  if (type.children.length !== 0) continue;

  let attrStrings = type.attributes.map(deserializer);

  innerDeserializerContent += `                    case "${typeName}":
                        return new ${typeName}(${attrStrings.join(', ')});
`;
}

deserializerContent += `${Array.from(deserializers.values()).join('')}
${innerDeserializerContent}                }
            }
        }
        return null;
    }
}`;

fs.writeFileSync(outDir + serializerDir + 'Deserializer.java', deserializerContent, 'utf-8');


let flatternerContent = `${makeHeader(__filename)}

package com.shapesecurity.shift.es2016.reducer;

import com.shapesecurity.functional.data.ImmutableList;
import com.shapesecurity.functional.data.Maybe;
import com.shapesecurity.shift.es2016.ast.*;
import javax.annotation.Nonnull;

public class Flattener extends MonoidalReducer<ImmutableList<Node>> {
    private static final Flattener INSTANCE = new Flattener();

    private Flattener() {
        super(new com.shapesecurity.functional.data.Monoid.ImmutableListAppend<>());
    }

    @Nonnull
    public static ImmutableList<Node> flatten(@Nonnull Program program) {
        return Director.reduceProgram(INSTANCE, program);
    }
`;

for (let typeName of Array.from(nodes.keys()).sort()) {
  let type = nodes.get(typeName);
  if (type.children.length !== 0) continue;

  let attrs = type.attributes.filter(f => isStatefulType(f.type));
  let attrStrings = attrs.map(f => `, @Nonnull ${toJavaType(f.type, 'ImmutableList<Node>')} ${sanitize(f.name)}`);
  flatternerContent += `
    @Nonnull
    @Override
    public ImmutableList<Node> reduce${typeName}(@Nonnull ${typeName} node${attrStrings.join('')}) {`;

  if (attrStrings.length === 0) {
    flatternerContent += `
        return ImmutableList.<Node>of(node);`;
  } else {
    flatternerContent += `
        return ImmutableList.<Node>of(node).append(super.reduce${typeName}(node${attrs.map(f => `, ${sanitize(f.name)}`).join('')}));`;
  }
  flatternerContent += `
    }
`;
}

flatternerContent += '}\n';

fs.writeFileSync(outDir + reducerDir + 'Flattener.java', flatternerContent, 'utf-8');


let rangeCheckerContent = `${makeHeader(__filename)}

package com.shapesecurity.shift.parser;

import com.shapesecurity.functional.data.ImmutableList;
import com.shapesecurity.functional.data.Maybe;
import com.shapesecurity.functional.data.Monoid;
import com.shapesecurity.shift.es2016.ast.*;
import com.shapesecurity.shift.es2016.reducer.MonoidalReducer;
import javax.annotation.Nonnull;

import static org.junit.Assert.assertTrue;

public class RangeCheckerReducer extends MonoidalReducer<RangeCheckerReducer.RangeChecker> {
    private final ParserWithLocation parserWithLocation;

    protected RangeCheckerReducer(ParserWithLocation parserWithLocation) {
        super(RangeChecker.MONOID);
        this.parserWithLocation = parserWithLocation;
    }

    private RangeChecker accept(Node node, RangeChecker innerBounds) {
        Maybe<SourceSpan> span = this.parserWithLocation.getLocation(node);
        assertTrue(span.isJust());
        RangeChecker outerBounds = new RangeChecker(span.just());
        assertTrue(outerBounds.start <= outerBounds.end);

        assertTrue(outerBounds.start <= innerBounds.start);
        assertTrue(innerBounds.end <= outerBounds.end);

        return outerBounds;
    }

    static class RangeChecker {
        public final static Monoid<RangeChecker> MONOID = new Monoid<RangeChecker>() {
            @Nonnull
            @Override
            public RangeChecker identity() {
                return new RangeChecker(Integer.MAX_VALUE, Integer.MIN_VALUE);
            }

            @Nonnull
            @Override
            public RangeChecker append(RangeChecker a, RangeChecker b) {
                assertTrue(a.end <= b.start);
                return new RangeChecker(a.start, b.end);
            }
        };
        public final int start, end;

        private RangeChecker(int start, int end) {
            this.start = start;
            this.end = end;
        }

        public RangeChecker(SourceSpan sourceSpan) {
            this(sourceSpan.start.offset, sourceSpan.end.offset);
        }
    }
`;

for (let typeName of Array.from(nodes.keys()).sort()) {
  let type = nodes.get(typeName);
  if (type.children.length !== 0) continue;

  let attrs = type.attributes.filter(f => isStatefulType(f.type));
  let attrStrings = attrs.map(f => `, @Nonnull ${toJavaType(f.type, 'RangeChecker')} ${sanitize(f.name)}`);
  rangeCheckerContent += `
    @Nonnull
    @Override
    public RangeChecker reduce${typeName}(@Nonnull ${typeName} node${attrStrings.join('')}) {`;

  rangeCheckerContent += `
      return accept(node, super.reduce${typeName}(node${attrs.map(f => `, ${sanitize(f.name)}`).join('')}));`;
  rangeCheckerContent += `
    }
`;
}

rangeCheckerContent += '}\n';

fs.writeFileSync(outDir + rangeCheckerDir + 'RangeCheckerReducer.java', rangeCheckerContent, 'utf-8');
