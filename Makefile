NAME = ft_malcolm

CC = gcc

#CFLAGS = -Wall -Wextra -Werror

HEADER = ft_malcolm.h

SRC = main.c \
		misc.c \
		ft_split.c \
		count_tab.c \
		ft_putlen.c

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