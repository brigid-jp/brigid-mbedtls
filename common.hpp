#ifndef BRIGID_MBEDTLS_COMMON_HPP
#define BRIGID_MBEDTLS_COMMON_HPP

#include <lua.hpp>

#include <new>
#include <stdexcept>
#include <utility>

namespace brigid {
  template <void (*T)(lua_State*)>
  struct function {
    static int value(lua_State* L) {
      try {
        int top = lua_gettop(L);
        T(L);
        int result = lua_gettop(L) - top;
        if (result > 0) {
          return result;
        } else {
          if (lua_toboolean(L, 1)) {
            lua_pushvalue(L, 1);
          } else {
            lua_pushboolean(L, true);
          }
          return 1;
        }
      } catch (const std::runtime_error& e) {
        lua_pushnil(L);
        lua_pushstring(L, e.what());
        return 2;
      } catch (const std::exception& e) {
        return luaL_error(L, "%s", e.what());
      }
    }
  };

  template <class T, class... T_args>
  inline T* new_userdata(lua_State* L, const char* name, T_args... args) {
    T* userdata = static_cast<T*>(lua_newuserdata(L, sizeof(T)));
    new(userdata) T(std::forward<T_args>(args)...);
#if LUA_VERSION_NUM >= 502
    luaL_setmetatable(L, name);
#else
    luaL_getmetatable(L, name);
    lua_setmetatable(L, -2);
#endif
    return userdata;
  }

  template <class T, void (*T_init)(T*), void (*T_free)(T*)>
  class context {
  public:
    context() : context_() { T_init(&context_); }
    ~context() { T_free(&context_); }
    context(const context&) = delete;
    context& operator=(const context&) = delete;
    T* get() { return &context_; }
  private:
    T context_;
  };

  void check(int);
}

#endif
