package dev.replayshield.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class AsciiTable {

    public enum Align {
        LEFT, CENTER, RIGHT
    }

    private final List<String> headers;
    private final List<Integer> widths;
    private final List<Align> aligns;
    private final List<List<String>> rows = new ArrayList<>();

    private AsciiTable(ColumnBuilder builder) {
        this.headers = List.copyOf(builder.headers);
        this.widths = List.copyOf(builder.widths);
        this.aligns = List.copyOf(builder.aligns);
    }

    public static ColumnBuilder columnBuilder() {
        return new ColumnBuilder();
    }

    public void addRow(String... columns) {
        if (columns.length != headers.size()) {
            throw new IllegalArgumentException("Column count mismatch");
        }
        rows.add(Arrays.asList(columns.clone()));
    }

    public String render() {
        List<Integer> effectiveWidths = calculateWidths();
        StringBuilder sb = new StringBuilder();
        String border = buildBorder(effectiveWidths);
        sb.append(border).append('\n');
        sb.append(buildRow(headers, effectiveWidths)).append('\n');
        sb.append(border).append('\n');
        for (List<String> row : rows) {
            sb.append(buildRow(row, effectiveWidths)).append('\n');
        }
        sb.append(border);
        return sb.toString();
    }

    private List<Integer> calculateWidths() {
        List<Integer> result = new ArrayList<>(widths);
        adjustWidths(result, headers);
        for (List<String> row : rows) {
            adjustWidths(result, row);
        }
        return result;
    }

    private void adjustWidths(List<Integer> result, List<String> values) {
        for (int i = 0; i < values.size(); i++) {
            int len = values.get(i) == null ? 0 : values.get(i).length();
            if (len > result.get(i)) {
                result.set(i, len);
            }
        }
    }

    private String buildBorder(List<Integer> widths) {
        StringBuilder sb = new StringBuilder("+");
        for (int width : widths) {
            sb.append("-".repeat(width + 2)).append('+');
        }
        return sb.toString();
    }

    private String buildRow(List<String> row, List<Integer> widths) {
        StringBuilder sb = new StringBuilder("|");
        for (int i = 0; i < row.size(); i++) {
            sb.append(' ')
                    .append(pad(row.get(i), widths.get(i), aligns.get(i)))
                    .append(' ')
                    .append('|');
        }
        return sb.toString();
    }

    private String pad(String value, int width, Align align) {
        String txt = value == null ? "" : value;
        if (txt.length() > width) {
            return txt.substring(0, width);
        }
        int diff = width - txt.length();
        return switch (align) {
            case LEFT -> txt + " ".repeat(diff);
            case RIGHT -> " ".repeat(diff) + txt;
            case CENTER -> " ".repeat(diff / 2) + txt + " ".repeat(diff - diff / 2);
        };
    }

    public static final class ColumnBuilder {
        private final List<String> headers = new ArrayList<>();
        private final List<Integer> widths = new ArrayList<>();
        private final List<Align> aligns = new ArrayList<>();

        public ColumnBuilder addColumn(String header, int width, Align align) {
            headers.add(header);
            widths.add(Math.max(1, width));
            aligns.add(align == null ? Align.LEFT : align);
            return this;
        }

        public AsciiTable build() {
            if (headers.isEmpty()) {
                throw new IllegalStateException("At least one column is required");
            }
            return new AsciiTable(this);
        }
    }
}
