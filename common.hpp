#ifndef BRIGID_MBEDTLS_COMMON_HPP
#define BRIGID_MBEDTLS_COMMON_HPP

#include <lua.hpp>
#include <cstddef>
#include <new>
#include <stdexcept>
#include <utility>

namespace brigid {
  bool runtime_error_policy_is_error(lua_State*);

  class stack_guard {
  public:
    stack_guard(const stack_guard&) = delete;
    stack_guard& operator=(const stack_guard&) = delete;

    explicit stack_guard(lua_State* L) : state_(L), top_(lua_gettop(L)) {}

    ~stack_guard() {
      lua_settop(state_, top_);
    }

  private:
    lua_State* state_;
    int top_;
  };

  template <void (*T)(lua_State*)>
  struct function {
    static int value(lua_State* L) {
      auto top = lua_gettop(L);
      try {
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
        lua_settop(L, top);
        if (runtime_error_policy_is_error(L)) {
          return luaL_error(L, "%s", e.what());
        } else {
          lua_pushnil(L);
          lua_pushstring(L, e.what());
          return 2;
        }
      } catch (const std::exception& e) {
        lua_settop(L, top);
        return luaL_error(L, "%s", e.what());
      }
    }
  };

  class string_reference {
  public:
    string_reference(const unsigned char* data, std::size_t size) : data_(data), size_(size) {}

    const unsigned char* data() const {
      return data_;
    }

    std::size_t size() const {
      return size_;
    }

  private:
    const unsigned char* data_;
    std::size_t size_;
  };

  inline string_reference check_string_reference(lua_State* L, int arg) {
    std::size_t size = 0;
    const auto* data = reinterpret_cast<const unsigned char*>(luaL_checklstring(L, arg, &size));
    return string_reference(data, size);
  }

  template <class T>
  inline void push_string_reference(lua_State* L, const T& source) {
    lua_pushlstring(L, reinterpret_cast<const char*>(source.data()), source.size());
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

    thread_reference() : thread_(), ref_(LUA_NOREF) {}

    explicit thread_reference(lua_State* L) : thread_(), ref_(LUA_NOREF) {
      thread_ = lua_newthread(L);
      ref_ = luaL_ref(L, LUA_REGISTRYINDEX);
    }

    thread_reference(thread_reference&& that) : thread_(that.thread_), ref_(that.ref_) {
      that.reset();
    }

    ~thread_reference() {
      unref();
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
    lua_State* thread_;
    int ref_;

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

    context() : context_() {
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

    static T* optional(lua_State* L, int arg) {
      if (lua_isnoneornil(L, arg)) {
        stack_guard guard(L);
        return T::get_default(L);
      } else {
        return check(L, arg);
      }
    }

    static T* test(lua_State* L, int index) {
#if LUA_VERSION_NUM >= 502
      return static_cast<T*>(luaL_testudata(L, index, T::name));
#else
      stack_guard guard(L);
      if (T* userdata = static_cast<T*>(lua_touserdata(L, index))) {
        if (lua_getmetatable(L, index)) {
          luaL_getmetatable(L, T::name);
          if (lua_rawequal(L, -1, -2)) {
            return userdata;
          }
        }
      }
      return nullptr;
#endif
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
    T_context context_;
  };

  void check(int);
}

#endif
