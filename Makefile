NAME = ft_malcolm

CC = clang

CFLAGS = -Wall -Wextra -Werror -g

HEADER = ft_malcolm.h

SRC = 	networking.c \
		misc.c \
		main.c	

OBJ = $(SRC:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(OBJ) -o $(NAME)

%.o: %.c
	$(CC) -c $< $(CFLAGS)
clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all re clean fclean