#ifndef BRIGID_MBEDTLS_COMMON_HPP
#define BRIGID_MBEDTLS_COMMON_HPP

#include <lua.hpp>
#include <cstddef>
#include <new>
#include <stdexcept>
#include <utility>

namespace brigid {
  template <void (*T)(lua_State*)>
  struct function {
    static int value(lua_State* L) {
      try {
        auto top = lua_gettop(L);
        T(L);
        auto result = lua_gettop(L) - top;
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

  class string_reference {
  public:
    string_reference(const char* data, std::size_t size) : data_(data), size_(size) {}

    const char* data() const {
      return data_;
    }

    std::size_t size() const {
      return size_;
    }

  private:
    const char* data_;
    std::size_t size_;
  };

  inline string_reference check_string_reference(lua_State* L, int arg) {
    std::size_t size = 0;
    const char* data = luaL_checklstring(L, arg, &size);
    return string_reference(data, size);
  }

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

  inline int abs_index(lua_State* L, int index) {
#if LUA_VERSION_NUM >= 502
    return lua_absindex(L, index);
#else
    if (index > 0 || index <= LUA_REGISTRYINDEX) {
      return index;
    } else {
      return lua_gettop(L) + index + 1;
    }
#endif
  }

  inline void set_field(lua_State* L, int index, const char* key, lua_Integer value) {
    index = abs_index(L, index);
    lua_pushinteger(L, value);
    lua_setfield(L, index, key);
  }

  template <void (*T)(lua_State*)>
  inline void set_field(lua_State* L, int index, const char* key, function<T>) {
    index = abs_index(L, index);
    lua_pushcfunction(L, function<T>::value);
    lua_setfield(L, index, key);
  }

  class thread_reference {
  public:
    thread_reference(const thread_reference&) = delete;
    thread_reference& operator=(const thread_reference&) = delete;

    thread_reference() = default;

    ~thread_reference() {
      unref();
    }

    explicit thread_reference(lua_State* L) {
      thread_ = lua_newthread(L);
      ref_ = luaL_ref(L, LUA_REGISTRYINDEX);
    }

    thread_reference(thread_reference&& that) : thread_(that.thread_), ref_(that.ref_) {
      that.reset();
    }

    thread_reference& operator=(thread_reference&& that) {
      if (this != &that) {
        unref();
        thread_ = that.thread_;
        ref_ = that.ref_;
        that.reset();
      }
      return *this;
    }

    explicit operator bool() const {
      return thread_;
    }

    lua_State* get() const {
      return thread_;
    }

  private:
    lua_State* thread_ = nullptr;;
    int ref_ = LUA_NOREF;

    void reset() {
      thread_ = nullptr;
      ref_ = LUA_NOREF;
    }

    void unref() {
      if (lua_State* T = get()) {
        luaL_unref(T, LUA_REGISTRYINDEX, ref_);
        reset();
      }
    }
  };

  template <class T, class T_context, void (*T_init)(T_context*), void (*T_free)(T_context*)>
  class context {
  public:
    context(const context&) = delete;
    context& operator=(const context&) = delete;

    context() {
      T_init(&context_);
    }

    ~context() {
      T_free(&context_);
    }

    T_context* get() {
      return &context_;
    }

    static T* check(lua_State* L, int arg) {
      return static_cast<T*>(luaL_checkudata(L, arg, T::name));
    }

    static T* construct(lua_State* L) {
      return new_userdata<T>(L, T::name);
    }

    static void impl_constructor(lua_State* L) {
      construct(L);
    }

    static void impl_destructor(lua_State* L) {
      check(L, 1)->~T();
    }

    using constructor = function<impl_constructor>;
    using destructor = function<impl_destructor>;

  private:
    T_context context_ = {};
  };

  void check(int);
}

#endif
