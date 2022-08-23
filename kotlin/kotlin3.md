# **函数** 

### **命名参数**
调用函数时，可以显式标明参数的名称。如果指定了一个参数的名称，那它其后的参数都要标明名称，命名参数的顺序与函数定义的顺序不一定要一致
```kotlin
fun test(v1:Int, v2:Int, v3:Int) {
    println("v1=$v1, v2=$v2, v3=$v3")
}

fun main(args : Array<String>) {
    test(1, 2, 3)
    test(1, v2=3, v3=4)
    test(1, v3=4, v2=5)
//    test(1, v3=4, 3) //编译出错
}
```
> 调用非Kotlin函数时不能使用命名参数。比如：Java函数，Android框架函数

---
### **默认参数值**
Java 的另 个普遍存在的问题是， 些类的重载函数实在太多了。这些重载，原本是为了向后兼容 ，方便这些 API 的使用者，又或者出于别的原因，但导致的最终结果是一致的 ：重复。这些 参数名和类型被重复了一遍又一遍  

在Kotlin 中，可以在声明函数的时候 ，指定参数的默认值，这样就可以避免创
建重载的函数。也可以用命名参数指定具体参数值
```kotlin
fun test(v1:Int=3, v2:Int=4, v3:Int=5) {
    println("v1=$v1, v2=$v2, v3=$v3")
}

fun main(args : Array<String>) {
    test()
    test(8)
    test(9, 10)
    test(1, 2, 3)
    test(v2=3)
    test(v1=4, v3=6)
}
```
> 注意，参数的默认值是被编码到被调用的函数中，而不是调用的地方。如果你改变了参数的默认值并重新编译这个函数，没有给参数重新赋值的调用者，将会开始使用新的默认值。   

> Java函数没有默认值，从Java调用Kotlin默认参数的函数时，必须指定全部的参数。如果需要从 Java 代码中做频繁的调用，而且希它能对 Java 的调用者更简便，可以用@JvmOverloads 注解它。这个指示编译器生成 Java 重载函数，从最后一个开始省略每个参数。

---
### **顶层函数和属性**
可以消除静态工具类。把函数接放到代码文件的顶层，不用从属于 任何的类 。这些放在文 件顶层的函数依然是包内的成员，如果你需要从包外访问它，则需要 import 但不再需要额外包一层
```kotlin
/* Join.kt */
package strings
fun joinToString (... ) : String { ... }

/* Java */
package strings;
public class JoinKt {
public static String joinToString(..){...}
```
顶层函数对应用的就是Java的public static 函数。Kotlin文件对应的Java类是：文件名Kt，然后就可以像调用静方法一样调用。比如JoinKt.joinToString

> 可以在文件的开头，也就是声明包的前面加 `@file:JvmName ("StringFunctions")`，改变生成的Java文件名字。
 
顶层属性和顶层函数一样都是声明在类外部。默认情况下，顶层属性是private static，是通过访问器暴露给 Java 使用的（如果是 val 就只有 geter ，如果是 var 就对应 geter setter）。如果想用Java的public static，则用 const val 声明变量
```kotlin
var counter = 1
const val test:Int = 1
```

---
### **扩展函数和属性**
给现有类库增加函数，和普通的函数声明类似，在函数名加上你要扩展的类名和 . 
```kotlin
fun String.lastChar(): Char = this.get(this.length - 1)
```
前面的String称为接收者类型，调用这个函数的那个对象称为接收者对象，即后面的this
,this也可以省略，可以直接访问衩扩展的类的方法和属性。

> **注意：** 扩展函数并不允许你打破它的封装性。和在类内部定义的方法不同的是 ，扩展函数不能访问私有的或者是受保护的成员

对于定义的扩展函数，它不会自动地在整个项目范围内生效 相反，如果你要使用它，需要进行导入，就像其他任何的类或者函数  

可以使用关键字 as 修改导入的类或者函数名称，解决命名冲突的问题：  
`import strings.lastChar as last`

实质上，扩展函数是静态函数，它把调用对象作为了它的第一个参数 调用扩展函数，不会创建适配的对象或者任何运行时的额外消耗这使得从 Java 中调用 Kotlin 的扩展函数变得非常简单：调用这个静态函数，然后把接收者对象作为第一个参数传进去即可

扩展函数并不是类的一部分，它是声明在类之外的。尽管可以给基类和子类都分别定义一个同名的扩展函数，当这个函数被调用时，它是由该变量的静态类型所决定的，而不是这个变量的运行时类型。

> **注意：** 如果一个类的成员函数和扩展函数有相同的签名，成员函数往往会被
优先使用

扩展属性和扩展方法声明方式类似，也是在普通的变量声明前加上类名和.，它也一个接收者类型和接收者对象。扩展属性没有任何状态，因为没有合适的地方来存储它，本质上还是扩展方法，只不过使用了一种短语法
```kotlin
val String.lastChar: Char
    get() = get(length - 1)

var StringBuilder.lastChar: Char
    get () = get(length - 1)
    set(value: Char) {
        this.setCharAt(length - 1, value)
    }
```
> **注意：** 当从Java中访问扩展属性的时候，应该显式地调用它的getter函数。比如
`StringUtilKt.getLastChar ("Java")`

---
### **可变参数和中缀调用**
可变参数用 vararg 声明，相当于Java中的参数后跟三个点...  
```kotlin
fun <T> listOf(vararg values: T): List<T> {...}

/* Java */
public <T> List<T> listOf(T... values){...}
```

Kotlin和Java 之间的另一个区别是，当需要传递的参数己经包装在数组中时，调用该函数的语法Java中，可以按原样传递数组，而Kotlin则要求你显式地解包数组，以便每个数组元素在函数中能作为单独的参数来调用。这个功能被称为展开运算符，而使用的时候，不过是在对应的参数前面放*号
```kotlin
fun main(args : Array<String>) {
    arrayListOf(*args)
}
```
> **注意：** 在Kotlin 1.3版本上不用展开，直接传递数组即可

中缀调用不是一种内置结构，而是一种特殊的函数调用。在中缀调用中，函数名称直接放在目标对象名称和参数之间。
```kotlin
 val map= mapOf(1 to "one", 7 to "seven ", 53 to "fifty-three")
    
    1.to("one")
    1 to "one"
```
中缀函数用 infix 修饰，只可修饰成员函数和扩展函数，并且函数只能有一个参数
```kotlin
infix fun String.test(a :Int)=null
```
解构声明在循环的时候见过（list.withIndex）。解构是用类实例去初始化变量。

```kotlin
/* to 函数在Kotlin库的声明，它返回的是一个Pair对象 */
public infix fun <A, B> A.to(that: B): Pair<A, B> = Pair(this, that)

val (key, value) = 1 to "one"
```

---
### **字符串和正则表达式处理**
Java的 String.split 函数把传入的字符串当正则处理，而Kotlin正相反，它把参数当普通的字符串处理，仅当需要正则的时候，需要显式的创建一个Regex类型  
```kotlin
println ("12.345-6.A". split (" \\. !".toRegex ()))
```
三重引号不会对字符串中的特殊字符转义，也会保留换行符，TAB等

---
### **局部函数**
局部函数是在一个函数的内部定义函数  

解决重复代码的一个方法就是用Extract Method方式重构代码，但这会生成许多小的方法，很多只有一个调用的点。Kotlin提供了一个更整洁的方案，可以在函数中嵌套这些提取的函数，这样既可以获得所需的结构，也无须额外的语法开销。

局部函数可以访问所在函数中的所有参数和变量