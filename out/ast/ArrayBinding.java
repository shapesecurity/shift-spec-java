// Generated by ast.js
/**
 * Copyright 2018 Shape Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
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


package com.shapesecurity.shift.es2016.ast;

import javax.annotation.Nonnull;
import com.shapesecurity.functional.data.HashCodeBuilder;
import com.shapesecurity.functional.data.ImmutableList;
import com.shapesecurity.functional.data.Maybe;

public class ArrayBinding implements Node, BindingPattern {
    @Nonnull
    public final ImmutableList<Maybe<BindingBindingWithDefault>> elements;

    @Nonnull
    public final Maybe<Binding> rest;


    public ArrayBinding (@Nonnull ImmutableList<Maybe<BindingBindingWithDefault>> elements, @Nonnull Maybe<Binding> rest) {
        this.elements = elements;
        this.rest = rest;
    }


    @Override
    public boolean equals(Object object) {
        return object instanceof ArrayBinding && this.elements.equals(((ArrayBinding) object).elements) && this.rest.equals(((ArrayBinding) object).rest);
    }


    @Override
    public int hashCode() {
        int code = HashCodeBuilder.put(0, "ArrayBinding");
        code = HashCodeBuilder.put(code, this.elements);
        code = HashCodeBuilder.put(code, this.rest);
        return code;
    }

}
