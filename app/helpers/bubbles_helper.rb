module BubblesHelper
  BUBBLE_ROTATION = %w[ 90 80 75 60 45 35 25 5 -45 -40 -75 ]
  BUBBLE_SIZE = [ 14, 16, 18, 20, 22 ]
  MIN_THRESHOLD = 7

  def bubble_rotation(bubble)
    value = BUBBLE_ROTATION[Zlib.crc32(bubble.to_param) % BUBBLE_ROTATION.size]

    "--bubble-rotate: #{value}deg;"
  end

  def bubble_size(bubble)
    total = MIN_THRESHOLD + bubble.boosts.size + bubble.comments.size
    value = BUBBLE_SIZE.min_by { |size| (size - total).abs }

    "--bubble-size: #{value}cqi;"
  end
end
