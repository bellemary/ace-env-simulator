package com.ace.envsimulator.ui;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import com.ace.envsimulator.R;
import com.ace.envsimulator.model.DetectionResult;
import com.ace.envsimulator.model.DetectionStatus;
import java.util.ArrayList;
import java.util.List;

public final class DetectionResultAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {
    public interface Listener { void onOpen(DetectionResult result); }

    private static final int TYPE_SECTION = 0;
    private static final int TYPE_ITEM = 1;

    private final Listener listener;
    private final List<ListItem> items = new ArrayList<>();
    private boolean advanced;

    public DetectionResultAdapter(Listener listener) { this.listener = listener; }

    public void setAdvanced(boolean advanced) {
        this.advanced = advanced;
        notifyDataSetChanged();
    }

    public void submitItems(List<ListItem> values) {
        items.clear();
        items.addAll(values);
        notifyDataSetChanged();
    }

    @Override public int getItemViewType(int position) {
        return items.get(position).isSection ? TYPE_SECTION : TYPE_ITEM;
    }

    @NonNull @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LayoutInflater inflater = LayoutInflater.from(parent.getContext());
        if (viewType == TYPE_SECTION) {
            return new SectionHolder(inflater.inflate(R.layout.row_section, parent, false));
        }
        return new ItemHolder(inflater.inflate(R.layout.row_detection, parent, false));
    }

    @Override public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        ListItem item = items.get(position);
        if (holder instanceof SectionHolder) {
            ((SectionHolder) holder).bind((SectionItem) item);
        } else if (holder instanceof ItemHolder) {
            ((ItemHolder) holder).bind(((ResultItem) item).result, advanced, v -> {
                if (listener != null) listener.onOpen(((ResultItem) items.get(holder.getBindingAdapterPosition())).result);
            });
        }
    }

    @Override public int getItemCount() { return items.size(); }

    // ============== List item model ==============
    public static abstract class ListItem {
        public final boolean isSection;
        ListItem(boolean isSection) { this.isSection = isSection; }
    }

    public static final class SectionItem extends ListItem {
        public final String title;
        public final String countText;
        public final int accentColorRes;
        public SectionItem(String title, String countText, int accentColorRes) {
            super(true);
            this.title = title;
            this.countText = countText;
            this.accentColorRes = accentColorRes;
        }
    }

    public static final class ResultItem extends ListItem {
        public final DetectionResult result;
        public ResultItem(DetectionResult result) { super(false); this.result = result; }
    }

    // ============== View holders ==============
    static final class SectionHolder extends RecyclerView.ViewHolder {
        final View sectionAccent;
        final TextView sectionTitle;
        final TextView sectionCount;
        SectionHolder(View item) {
            super(item);
            sectionAccent = item.findViewById(R.id.sectionAccent);
            sectionTitle = item.findViewById(R.id.sectionTitle);
            sectionCount = item.findViewById(R.id.sectionCount);
        }
        void bind(SectionItem section) {
            sectionTitle.setText(section.title);
            sectionCount.setText(section.countText);
            sectionAccent.setBackgroundResource(section.accentColorRes);
        }
    }

    static final class ItemHolder extends RecyclerView.ViewHolder {
        final View indicator;
        final TextView title, category, summary, status;
        ItemHolder(View item) {
            super(item);
            indicator = item.findViewById(R.id.statusIndicator);
            title = item.findViewById(R.id.title);
            category = item.findViewById(R.id.category);
            summary = item.findViewById(R.id.summary);
            status = item.findViewById(R.id.status);
        }
        void bind(DetectionResult result, boolean advanced, View.OnClickListener click) {
            title.setText(result.title);
            category.setText(advanced ? result.category : result.category + " · 置信度 " + result.confidence + "%");
            summary.setText(result.summary);
            status.setText(advanced
                    ? result.status == DetectionStatus.PASS ? "已读取"
                    : result.status == DetectionStatus.RISK ? "已发现" : "需要确认"
                    : result.status.label);
            int dotRes;
            int statusColorRes;
            if (result.status == DetectionStatus.PASS) {
                dotRes = advanced ? R.drawable.bg_dot_neutral : R.drawable.bg_dot_success;
                statusColorRes = advanced ? R.color.text_secondary : R.color.success;
            } else if (result.status == DetectionStatus.RISK) {
                dotRes = R.drawable.bg_dot_danger;
                statusColorRes = R.color.danger;
            } else {
                dotRes = R.drawable.bg_dot_warning;
                statusColorRes = R.color.warning;
            }
            indicator.setBackgroundResource(dotRes);
            int color = itemView.getContext().getResources().getColor(statusColorRes, itemView.getContext().getTheme());
            status.setTextColor(color);
            itemView.setOnClickListener(click);
        }
    }
}
