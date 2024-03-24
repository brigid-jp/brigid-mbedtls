#include <lua.hpp>

#include <mbedtls/entropy.h>

#include <iostream>
#include <new>
#include <stdexcept>
#include <utility>

namespace brigid {
  template <class T, void (*T_init)(T*), void (*T_free)(T*)>
  class context {
  public:
    context() : context_() { T_init(&context_); }
    ~context() { T_free(&context_); }
    context(const context&) = delete;
    context& operator=(const context&) = delete;
    T* get() { return &context_; }
    T* operator->() { return &context_; }
    T& operator*() { return context_; }
  private:
    T context_;
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


  namespace {
    using entropy_t = context<mbedtls_entropy_context, mbedtls_entropy_init, mbedtls_entropy_free>;

    void new_entropy(lua_State* L) {
      new_userdata<entropy_t>(L, "brigid.mbedtls.entropy");
    }

    void impl_gc(lua_State* L) {
      std::cerr << "entroypy.__gc\n";
      auto* self = static_cast<entropy_t*>(luaL_checkudata(L, 1, "brigid.mbedtls.entropy"));
      self->~entropy_t();
    }
  }

  void initialize_entropy(lua_State* L) {
    lua_newtable(L);
    {
      luaL_newmetatable(L, "brigid.mbedtls.entropy");
      lua_pushvalue(L, -2);
      lua_setfield(L, -2, "__index");

      lua_pushcfunction(L, function<impl_gc>::value);
      lua_setfield(L, -2, "__gc");

      lua_pop(L, 1);

      lua_newtable(L);
      lua_pushcfunction(L, function<new_entropy>::value);
      lua_setfield(L, -2, "__call");
      lua_setmetatable(L, -2);


    }
    lua_setfield(L, -2, "entropy");
  }
}
