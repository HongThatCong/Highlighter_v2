# Highlighter_v2
Highligher plugin, merge từ Highligher plugin của HexRays support và Highlight2

Build for IDA 7.x

Chi tiết về tính năng của 2 plugin này có thể xem tại các link sau:

1. Highligher:

https://www.hex-rays.com/blog/the-highlighter/

Nói nôm na là khi ta debug, trace thì những ea nào đã trace qua, có executed thì sẽ có prefix là "  " và đổi màu. 
Để ta dễ theo dõi hơn luồng thực thi hơn.

2. Highlight2:

http://oct0xor.github.io/2017/05/03/ida_coloring/

https://github.com/oct0xor/highlight2

Nói nôm na là chỉ change màu cho call instruction.

Tôi đã fix 1 vài bug nhỏ của hightlight2, thêm tính năng save options, thêm => vào trước call instruction để dễ thấy hơn.

Nhưng điểm yếu hiện tại của highlight2 và plugin hiện tại là chỉ display được trên graph mode, trên disassembly view mode không được.

Tôi chưa tìm ra cách, nếu các bạn biết xin góp ý, chỉ giáo.

Chân chọng, bét xì ga..

Happy coding...

Coding for food and for fun :D
