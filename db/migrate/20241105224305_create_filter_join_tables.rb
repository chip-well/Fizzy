class CreateFilterJoinTables < ActiveRecord::Migration[8.0]
  def change
    create_join_table :filters, :tags do |t|
      t.index :filter_id
      t.index :tag_id
    end

    create_join_table :filters, :buckets do |t|
      t.index :filter_id
      t.index :bucket_id
    end

    create_join_table :filters, :assignees do |t|
      t.index :filter_id
      t.index :assignee_id
    end
  end
end
