# **Kotlin基础**
首先来个经典的Hello World
```kotlin
fun main(args : Array<String>) {
    println("Hello World")
}
```
* 关键字 fun 用来声明一个函数
* 参数类型写在名称后面，变量声明也一样
* 函数可以定义在文件的最外层，不用非放在类里
* 数组是一个类
* 使用 println 代替了 System.out.println。Kotlin标准库给Java标准库函数提供了很多包装方法
* 和许多其他现代语言一样，可以省略每行代码结尾的分号
---
### **函数**
```kotlin
fun max(a : Int, b : Int) : Int{
    return if(a > b ) a else b
}
```
函数声明以关键字 fun 开始，名称紧随其后，接下来是括号括起来的参数列表，参数列表后面跟着返回类型

> Kotlin中 if 是表达式，而不是语句，在Java中大多数控制结构都是语句，而在Kotlin中除了循环外大多数控制结构都是表达式。  
Java中的赋值操作是表达式，但在Kotlin中是语句。

因为它的函数体是单个表达式构成的，可以用这个表达式作函数体去掉花括号和return语句

```kotlin
fun max(a : Int , b: Int) : Int = if (a > b) a else b
```


还可以进一步简化，去掉返回类型
```kotlin
fun max(a: Int, b: Int ) = if (a > b) a else b
```
对于表达式体函数来说，编译器会分析函数体的表达式，把表达式的类型作为函数的返回类型，这种分析被称为类型推导。  
只有表达式体的函数才可以省略返回类型，对于代码块体函数必须显式的写出返回类型和return语句

---
### **变量**
```kotlin
val answer: Int = 42

val answer2 = 42
```
和表达式体函数一样，如果不指定变量类型，编译器可以推导出来

```kotlin
val answer: Int
answer = 42
```
如果没有初始化器，需要显式的指定类型

* val(value)————不可变引用，val 声明的变量不能在初始化之后再次赋值，对应的是Java的 final 变量
* var(variable)————可变引用，值可以改变，对应的是java的普通变量

默认情况下，尽可能的使用 val 变量，仅在必要的时候换成 var，使用不可变对象更接近函数式编程

---
### **字符串格式化**
```kotlin
fun main(args : Array<String>) {
    val str = "Hello World"
    println("value=$str, length=${str.length}")
    val n = 3
    println("number is ${if(n % 2 == 0) "even" else "odd"}")
}
```
可以在字符串内直接引用变量，变量前加 $,如果不是变量是一个表达式，则要在表达式上加大括号，还可以在双引号中嵌套引号

---
### **条件分支**
```kotlin
enum class Color{
    RED, BLUE, YELLOW, TEST1, TEST2
}
```
enum声明一个枚举类，它一个软关键字，只有出现在class前面时才有特殊意义，在其它地方可以当作普通名称用。class和enum不同，它一直是关键字

```kotlin
fun getColorString(color : Color){
    when(color){
        Color.RED -> "Red"
        Color.BLUE -> "Blue"
        Color.YELLOW -> "Yellow"
        Color.TEST1, Color.TEST2 -> "Test"
    }
}
```
when 相当于Java中的 switch，每个分支后面不写 break,可以把多个值合并到同一个分支，中间用逗号隔开  
java的 switch 只能使用常量， when 中使用任何对象，也可以不传值

```kotlin
fun mix(color1:Color, color2:Color) =
    when(setOf(color1, color2)){
        setOf(Color.RED, Color.BLUE) -> Color.TEST2
        setOf(Color.BLUE, Color.YELLOW) -> Color.TEST1
        else -> throw Exception("Unknown color")
    }

    fun mix2(color1:Color, color2:Color) =
        when{
            color1 == Color.RED && color2 == Color.BLUE-> {
                println("return value")
                Color.TEST2
            }
            color1 == Color.BLUE && color2 == Color.YELLOW -> Color.TEST1
            else -> throw Exception("Unknown color")
        }
```
上面第一个分支中的Color.TEST2就是 when 表达式的值  
kotlin中没有三目运算符 ? :, 可以用 if() a else b代替，因为 if 是表达式而不是语句

---
#### **智能转换**
如果判断过类型，则不需要类型转换。is 相当于Java的 instanceof, as 是类型强制转换
```kotlin
val value : Any = "test string"
    if(value is String){
//        val stringValue = value as String //不需要显式转换类型
        println("string.length is ${value.length}")
    }
```

---
### **循环**
while 和 do-while 和Java一样  
Kotlin 没有常规的Java for 循环，取而代之的是**区间**,使用 .. 运算符表示区间，区间是闭合的，包含最后一个值
```kotlin
    for(v in 1..10){
        println("value: $v")
    }

    for(v in 1..10 step 3){
        println("value: $v")
    }

    for(v in 10 downTo 1 step 2){
        println("value: $v")
    }

    for(v in 1 until 10){ // for(v in 1..10-1)
        println("value: $v")
    }
```
step 可以指定步长，步长可以为负值。downTo 是递减，until 是一个半闭合区间

```kotlin
    val mapTest = HashMap<String, String>()
    for(num in 0..9){
        mapTest[num.toString()] = (num + 1).toString()
    }

    for((key, value) in mapTest){
        println("key=$key, value=$value")
    }

    val list = arrayListOf("str1", "str2", "str3")
    for(item in list){
        println("list item: $item")
    }

    for((i, item) in list.withIndex()){
        println("list index=$i, item=$item")
    }
```
对map的赋值，取值可以用类似于数组的方法，等价于map.put(key, value), map.get(key)。(key, value)展开运算符，类似的还有对list的下标迭代

可以用 in 和 !in 检查是否在一个区间
```kotlin
    println("c in a..z: ${'w' in 'a'..'z'}")
    println("Kotlin  in Java..Scala: ${"Kotlin" in "Java".."Scala"}")
    val list = arrayListOf(1, 2, 3, 4, 5)
    println("3 in list: ${3 in list}")
```

---
### **Kotlin中的异常**
与Java异常类似，只不过Kotlin的异常是一个表达式  
和其它现在Jvm语言一样，Kotlin并不区分受检异常和非受检异常，不用在函数后面指定抛出的异常，调用函数可以处理也可以不处理。这是基于Java中使用异常的实践做出的决定，经验显示这些Java规则常常导致许多毫不意义的重新抛出异常或者忽略异常的代码，而且这些规则不能总是保护你免受可能发生的错误。