# Challenges Faced  

## Code Structure Challenge

One early challenge we faced was thinking of how to structure the skeleton code. Before any scanning logic could be implemented, we had to decide how to break the program into logical components, what each function's responsibility should be, and how data would flow between them. 

This required us to do some planning to avoid redundancy and make sure there was flexibility across different scan modes (connect, SYN, UDP). 

### Our Solution

We resolved this by first outlining the program's major tasks (such as resolving the target, checking that it was alive, choosing ports, etc) and then assigning each of these to a modular function. 

This modular design made the codebase easier to debug and more maintainable.
