## **Lambda表达式和成员引用**

Lambda表达式就是可以传递给其它函数一小段代码，在Java中通常用匿名内部类来实现， 函数式编程把函数当代一值传递，而不用先声明一个类，再实现方法，传递这个类的实例。使用lambda表达式代码可以更加简洁。

**Lambda表达式语法**
```kotlin
val sum = {x:Int, y:Int -> x + y} //将lambda赋值给变量
sum(3, 2) //调用函数

{println("Hello world")}() //直接调用lambda函数

run { println("Hello") } //用run函数调用
```

Kotlin的lambda表达式始终用花括号包围，箭头把实参列表和函数体隔离
开。可以把一个lambda表达式存在一个变量里，把变量当作普通函数对待。可以直接执行一个lambda表达式，但这样毫无意义，可以用库函数 run 去执行一个lambda。

```kotlin
fun main(args : Array<String>) {
    val list = arrayListOf(Person("p1", 12), Person("p2", 33))
    list.maxBy({p : Person -> p.age}) //1
    list.maxBy(){p:Person -> p.age} //2
    list.maxBy{p:Person->p.age} //3
    list.maxBy{p->p.age} //4
    list.maxBy{it.age} //5
}
```
上面例子是同一个lambda的不同写法，第一种是最完整的写法，Kotlin中规定:
* 如果lamda表达式是函数的最后一个参数可以放在括号外面去。1->2
* 当lambda是函数唯一实参时，可以去掉空括号。2->3
* 如果lambda的参数类型可以被推导出来，就不需要显式的指定它。3->4
* 如果当前上下文期望的lambda只有一个参数，且类型可以被推导出来，则可以省略参数用 **it** 代替。4->5

lambda表达式中最后一个表达式就是lambda的结果。

**在作用域中访问变量**

Lambda可以访问一个函数的参数和函数外的变量，不仅可以访问而且还可以修改。在Java中匿名内部类只允许访问final变量。

```kotlin
fun test(list : List<Int>){
    var count = 0
    list.forEach { 
        if(it % 2 == 0){
            count++
        }
    }
}
```

一般情况下，局部变量的生命周期只在这个函数内有效，如果被lambda捕捉了，使用这个变量的代码可以被存储，稍后执行。对于final变量，它的值和使用这个值的代码一起存储;对于非final变量，它的值被封装在一个特殊的包装器中，这样就可以改变这个值，它的引用会和lambda一起存储。

注意，如果lambda被用作事件处理器，或者其它异步执行的时候，lambda对局部变量的修改，只在执行的时候发生，像下面的函数始终返回0。
```kotlin
fun tryToCountButtonClicks(button: Button) : {
    var clicks = O
    button.onClick { clicks++ }
    return clicks
}
```

**成员引用**

Lambda是把代码块当作参数传递给函数，如果想要传递的代码已经被定义成了函数，可以直接把这个函数当作值传递。

```kotlin
class Person(val name : String, val age : Int)

fun Person.print()=println("name=$name, age=$age")

fun sayHello() = println("Hello")

fun main(args : Array<String>) {
    val list = arrayListOf(Person("p1", 12), Person("p2", 33))

    val getAge = Person::age
    list.maxBy(getAge)
    list.maxBy(Person::age)

    val sayHelloFun = ::sayHello //引用顶层函数
    run(sayHelloFun)
    run(::sayHello)

    val createPerson = ::Person //引用构造函数
    val p = createPerson("p3", 8)

    val pPrint = Person::print //引用扩展函数
}
```
像上面的Person::age，这种表达式称为成员引用。它创建了一个调用单个方法或访问单个属性的函数值。双冒号把类名称与你要引用的成员名称隔开。

还可以引用顶层函数，构造函数，扩展函数。

---
## **集合的函数式API**

filter：遍历集合，并选出应用给定lambda返回true的那些元素。它并不会改变集合中的元素。

map：对集合中的每一个元素应用给定的函数并把结果收集到一个新集合。map会对元素中的每个元素做变换。

all：集合中的有元素是否都满足给定lambda的条件，结果是布尔。

any：集合中是否有元素满足给定的lambda条件，结果是布尔。

find：返回匹配给空lambda的第一个元素，没有则返回null。

groupBy：把列表转换成一个分组的map，map中存储的是Map\<key, List<Item\>>

flatMap：首先根据给定的lambda对列表中的每个元素做变换，然后把多个列表合并成一个列表。

flatten：不做变换，只是平铺一个集合。

---
## **序列**
序列是一种惰性集合操作，像上节说的filter或者map，都会及早的创建中间集合，每一步的中间结果都会被存储在一个临时列表。**序列**可以避免创建这些临时对象。

```kotlin
list.map(Person::name).filter { it.startsWith("A")}
```
上面例子中map和filter都会创建一个列表，如果只有少量的元素还可以接受，但是如果有几百万的元素，效率将很低下。为了提高效率可以把集合改成序列：
```kotlin
list.asSequence()
            .map(Person::name)
            .filter { it.startsWith("A")}
            .toList()
```

Sequence接口只提供一个方法iterator,用来访问每个元素。序列中的求值是惰性的，不会产生中间结果。可以调用扩展函数asSequence将任意集合转成序列。

序列的操作分为两类：中间操作和末端操作。像上面的map, filter都称为中间操作，toList叫做末端操作。中间操作都是惰性的，返回的是一个序列，末端操作返回的是一个结果。如果少了末端操作，中间操作将不会被触发。

序列中的执行顺序也是和普通的集合不同的。像上面的例子如果是普通集合，则是对所有元素先执行map，然后再对所有元素执行filter。而序列不一样，对序列来说所有的操作都是按顺序应用到每一个元素上，然后再处理下一个元素。

```kotlin
val result = list.asSequence()
            .map(Person::name)
            .find { it.startsWith("A")}
println("result=$result")
```
这种执行顺序在某些情况下可以提高效率，比如上例中的find。如果使用集合需要对所有元素先做map,再去find。用序列的话，对每个元素先map再find，如果目标在列表前面的话就可以直接返回不用再去对后面的元素做map操作。

创建一个序列除了用asSequence外，还可以使用generateSequence，给定元素的前一个元素，会自动计算出下一个元素。下面是求100内自然数的和：
```kotlin
fun main(args : Array<String>) {
    val numbers = generateSequence(0) { it + 1 }
    val numberTo100 = numbers.takeWhile { it < 100 }
    println("sum=${numberTo100.sum()}")
}
```

---
## **函数式接口**

只有一个方法的接口叫做**函数式接口**,或者**SAM**接口，SAM表示单抽象方法。

Java中的Runnable, Callable, OnClickListener等等有很多这样的函数式接口。Kotlin允许在调用这些SAM接口时使用lambda表达式。

```kotlin
/* Java */
void postponeComputation(int delay, Runnable computation);

/* Kotlin */
postponeComputation(1000){println("Hello")} //1

postponeComputation(1000, object : Runnable{ //2
    override fun run(){
        println("Hello")
    }
})
```
上例中的1，编译器会自动把lambda转换成一个实现了Runnable接口的匿名类对象，就像例子中的2。但这两个还是有些区别，显示声明对象时每次调用都会创建新的实例，使用lambda不同，如果lambda没有访问任何来自定义它函数的变量，则相应的匿名类实例可以在多次调用之间重用。

```kotlin
val runnable = Runnable{println("Hello")}

postponeComputation(1000, runnable)
```
上面这两种方式是等价的。

如果lambda从包围它的作用域捕捉了变量，每次调用就不再重用一个实例，而是每次调用都创建一个新实例。

如果从方法中返回一个SAM接口的实例，不能返回lambda，而是要用SAM构造方法把它包装起来。像下面这样：
```kotlin
fun getRunnable():Runnable{
    return Runnable { println("Hello") }
}
```
> **Lambda和移除添加监听器**  
Lambda内部并没有匿名对象那样的this, 所以要在事件监听器中取消自己要用匿名对象，匿名对象中的this, 指向该接口的实例。

## **带接收者的Lambda**

**with函数**

with函数可以对一个对象执行多次操作，而不需要反复的写出对象名字。

```kotlin
fun getString() : String{
    val result = StringBuilder()
    for(letter in 'a'..'z'){
        result.append(letter)
    }
    return result.toString()
} 

fun getString2() = with(StringBuilder()){
    for(letter in 'a'..'z'){
        append(letter)
    }
    this.toString()
}
```
上面的getString, getString2返回相同的结果。getString2中with表达式的值，就是lambda表达式的值。

with表达式把第一个参数作为第二个参数传给它的lambda接收者。在lambda中也可以省略this。

**apply函数**

apply函数和with几乎一模一样，唯一的区别是apply会返回它的实参对象，也就是接收者对象。

```kotlin
fun getString3() = StringBuilder().apply {
    for(letter in 'a'..'z'){
        append(letter)
    }
}.toString()
```
apply在一定程度上来说可以实现Builder模式。比如构造一个TextView:
```kotlin
val textView = TextView(context).apply{
    text = "Hello"
    textSize = 20.0
}
```
---
## **高阶函数**

高阶函数就是用另一个函数作为形参或返回值的函数，也就是函数的参数里包含lambda函数的引用，或者返回值是lamda函数的引用。

**函数类型**

函数类型有点像C语言里的函数指针，就是存储函数的变量。像下面这样：

```kotlin
val function : (Int, String)->Int = { number, str ->
    println("Hello world\n")
    return 0
}
```
function就是一个函数类型的变量，和声明普通变量一样，只不过类型变成了描述函数类型的形式。

函数类型：将参数类型放在括号中，紧接着是一个箭头和函数的返回类型。

> 在声明一个普通函数时Unit可以省略，但是在声明函数类型时不可以省略。

```kotlin
val function1 : (Int, String)->Int? = { number, str ->
    println("Hello world\n")
    return 0
}
val function2 : ((Int, String)->Int)? = null

```
注意上面两个函数变量的区别，function是一个返回可空类型，但它自身不能为空。function2是一个返回非空类型的可空函数类型。

下面是一个高阶函数的声明：
```kotlin
fun request(url : String, callback: (code: Int, response: String)->Unit){
    callback(200, "ok")
}
```
调用函数参数和调用普通函数一样。函数类型也可以有默认参数。

>原理：一个函数类型的变量是FunctionN接口的实现。Function0<R>, Function1<P1, R>

如果要在JAVA中调用Kotlin的高阶函数，像下面这样:
```kotlin
TestKt.request("url", new Function2<Integer, String, Unit>() {
                @Override
                public Unit invoke(Integer integer, String s) {
                    return Unit.INSTANCE;
                }
            });
```
Kotlin中定义了一些FunctionN的方法，FunctionN中最后一个类型参数为返回值，前面的是函数类型的参数。如果在java中调用kotlin中的Unit方法，要return Unit.INSTANCE。

每个函数类型都有个invoke方法，可以显式调用：
```kotlin
fun main(args : Array<String>) {
    val funT : (Int, Int)->Int = {a, b-> a + b}
    funT.invoke(3, 4)
}
```

**内联函数：消除lambda带来的性能开销**

内联函数是在函数前加inline。也可以在参数前用noinline修饰符，强制不允许内联。内联函数的函数体会被直接替换到函数被调用的地方。
```kotlin
inline fun <T> synchronized(lock : Lock, action: ()->T) : T{
    lock.lock()
    try {
        return action()
    }finally {
        lock.unlock()
    }
}

fun main(args : Array<String>) {
    val lock = ReentrantLock()
    
    synchronized(lock){
        println("Hello")
    }

    /* 最终会展开成这种样子
    lock.lock()
    try {
        println("Hello")
    }finally {
        lock.unlock()
    }
     */
}
```

内联函数只有在调用点数才会被内联。

内联的限制：
如果只有参数被调用，则可以内联，如果参数被保存起来，则不能内联
在JAVA中调用内联函数会被编译成普通的函数调用

使用inline函数只能提高带有lambda参数的函数的性能，其它情况需要额外的度量和研究
内联函数应该尽可能的小，如果函数太长，还是用普通函数

**高阶函数中的控制流**

内联函数是非局部返回，非内联函数是局部返回。内联函数最终会展开，所以如果在内联函数中使用了return，外部函数也会返回。

使用标签返回：在lambda花括号前写一个标签名加@，在return@label

people.forEach label@{
	return@label
}

局部返回可以用匿名函数，匿名函数声明如下：
```kotlin
fun main(args : Array<String>) {
    val list = arrayListOf(1, 2, 3)
    list.forEach(fun (index : Int){
        println("list[$index]=${list[index - 1]}")
    })
}
```