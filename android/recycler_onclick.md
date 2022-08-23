​
# Android RecyclerView设置点击事件

在Adapter中实现事件绑定，自定义一个OnItemClickListener的接口， 如果要增加点击事件，则调用bindClick方法，给View加一个position的tag，当View被点击的时候，把View和position都返回给用户，有了position基本上可以做任何操作了。代码很简单。
```java
import android.content.Context;
import android.support.v7.widget.RecyclerView;
import android.view.LayoutInflater;
import android.view.View;

import java.util.List;

/**
 * Created by GouHao on 2017/9/16.
 */

public abstract class BaseRecyclerAdapter<VH extends RecyclerView.ViewHolder, D extends Object>
        extends RecyclerView.Adapter<VH> implements View.OnClickListener {
    protected Context context;
    protected LayoutInflater layoutInflater;
    protected List<D> data;
    protected OnItemClickListener onItemClickListener;

    public BaseRecyclerAdapter(Context context, List<D> data) {
        this.context = context;
        this.data = data;
        layoutInflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
    }

    @Override
    public int getItemCount() {
        return data.size();
    }

    public void bindClick(View view, int position) {
        view.setTag(R.id.item_position, position);
        view.setOnClickListener(this);
    }

    public D getItem(int position) {
        return data.get(position);
    }

    @Override
    public void onClick(View v) {
        Object tag = v.getTag(R.id.item_position);
        if(tag == null || !(tag instanceof Integer)) {
            return;
        }
        int position = (int) tag;
        if(onItemClickListener != null) {
            onItemClickListener.onItemClick(v, position);
        }
    }

    public void setOnItemClickListener(OnItemClickListener onItemClickListener) {
        this.onItemClickListener = onItemClickListener;
    }

    public interface OnItemClickListener{
        void onItemClick(View view, int position);
    }
}
```

​