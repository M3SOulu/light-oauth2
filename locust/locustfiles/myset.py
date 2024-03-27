__all__ = ['set_with_choice']

class set_with_choice(set):

    def choice(self):
        i = self.pop()
        self.add(i)
        return i
