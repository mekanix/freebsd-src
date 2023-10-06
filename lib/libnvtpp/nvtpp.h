#ifndef		_NVTPP_H_
#define		_NVTPP_H_

#include <map>
#include <string>
#include <vector>


namespace nvtpp
{
typedef std::vector<uint8_t> packed_t;
enum class Type
{
	BOOL,
	NUMBER,
	STRING,
	NULLPTR,
	TREE,
	DESC,
	ARRAY_BOOL,
	ARRAY_NUMBER,
	ARRAY_STRING,
	ARRAY_TREE,
	ARRAY_DESC,
};


class Pair
{
	public:
		Pair(const std::string &name = "");
		virtual ~Pair();

		const std::string & name();
		virtual size_t size() const;
		virtual size_t data_size() const = 0;
		virtual Type type() const = 0;
		virtual uint8_t nvtype() const = 0;
		virtual bool pack(packed_t &data) = 0;
		virtual bool pack_raw(packed_t &data) = 0;
		virtual bool is_array() const;
		void parent(Pair *);

		virtual void get(bool &);
		virtual void get(uint64_t &);
		virtual void get(std::string &);
		virtual void get(int64_t &);

		virtual void set(const bool &);
		virtual void set(const int &);
		virtual void set(const uint64_t &);
		virtual void set(const std::string &);
		virtual void set(const char *);
		virtual void set(const int64_t &);

	protected:
		std::string _name;
		Pair *_parent;
};


class Bool: public Pair
{
	public:
		Bool(const std::string &name = "", const bool &value = false);

		virtual size_t size() const;
		virtual size_t data_size() const;
		virtual Type type() const;
		virtual uint8_t nvtype() const;
		virtual void get(bool &);
		virtual void set(const bool &);
		virtual bool pack(packed_t &data);
		virtual bool pack_raw(packed_t &data);

	protected:
		bool _value;
};


class Number : public Pair
{
	public:
		Number(const std::string &name = "", const uint64_t &value = 0);

		virtual size_t size() const;
		virtual size_t data_size() const;
		virtual Type type() const;
		virtual uint8_t nvtype() const;
		virtual void get(uint64_t &);
		virtual void set(const int &);
		virtual void set(const uint64_t &);
		virtual bool pack(packed_t &data);
		virtual bool pack_raw(packed_t &data);

	protected:
		uint64_t _value;
};


class String: public Pair
{
	public:
		String(const std::string &name = "", const std::string &value = "");

		virtual size_t size() const;
		virtual size_t data_size() const;
		virtual Type type() const;
		virtual uint8_t nvtype() const;
		virtual void get(std::string &);
		virtual void set(const char *);
		virtual void set(const std::string &);
		virtual bool pack(packed_t &data);
		virtual bool pack_raw(packed_t &data);

	protected:
		std::string _value;
};


class Null: public Pair
{
	public:
		Null(const std::string &name = "");

		virtual size_t size() const;
		virtual size_t data_size() const;
		virtual Type type() const;
		virtual uint8_t nvtype() const;
		virtual bool pack(packed_t &data);
		virtual bool pack_raw(packed_t &data);
};


class Descriptor: public Pair
{
	public:
		Descriptor(const std::string &name = "", const int64_t &value = -1);

		virtual size_t size() const;
		virtual size_t data_size() const;
		virtual Type type() const;
		virtual uint8_t nvtype() const;
		virtual void get(int64_t &);
		virtual void set(const int &);
		virtual void set(const int64_t &);
		virtual bool pack(packed_t &data);
		virtual bool pack_raw(packed_t &data);

	protected:
		int64_t _value;
};


class Tree : public Pair
{
	public:
		Tree(const std::string &name = "");

		virtual size_t size() const;
		virtual size_t data_size() const;
		void add(Pair *pair);
		Pair * remove(const std::string &name);
		virtual bool pack(packed_t &data);
		virtual bool pack_raw(packed_t &data);
		bool pack_size(packed_t &data);
		bool unpack(void *data, size_t size);
		Pair * find(const std::string &name);
		virtual Type type() const;
		virtual uint8_t nvtype() const;

	protected:
		size_t _index;
		std::map<std::string, Pair *> _value;
		bool _unpack(void *&data, size_t &size);
};


template <typename T>
class Array: public Pair
{
	public:
		Array(const std::string &name = "");

		virtual size_t size() const;
		virtual size_t data_size() const;
		void add(T *pair);
		T * remove(const size_t &index);
		virtual Type type() const;
		virtual uint8_t nvtype() const;
		Pair * operator [] (const size_t &index);
		virtual bool is_array() const;
		virtual bool pack(packed_t &data);
		virtual bool pack_raw(packed_t &data);

	protected:
		std::vector<T *> _value;
};
}

#endif // _NVTPP_H_
