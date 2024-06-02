#include "nvtpp.h"
#include <sys/nv.h>

#include <stdexcept>
#include <sstream>
#include <string>
#include <iostream>

namespace nvtpp
{

static const packed_t header = {0x6c, 0x00};

struct nvtree_header {
	uint8_t		magic;
	uint8_t		version;
	uint8_t		flags;
	uint64_t	descriptors;
	uint64_t	size;
} __packed;

struct nvtpair_header {
	uint8_t		type;
	uint16_t	namesize;
	uint64_t	datasize;
	uint64_t	nitems;
} __packed;

static void
pack_data(packed_t &packed, const std::string &data)
{
	for (const auto &ch: data) {
		packed.push_back(ch);
	}
	packed.push_back(0);
}

static void
offset_read(void *&data, size_t &size, auto *&var)
{
	uint8_t *res = (uint8_t *)data;
	size_t s = sizeof(*var);

	if (data != nullptr)
	{
		var = (decltype(var))data;
		size -= s;
		res += s;
		data = (void *)res;
	}
}


template<typename T>
static void *
hook_var(void *data, T *&var)
{
	var = (T *)data;
	return (void *)(((uint8_t *)data) + sizeof(*var));
}

static void
pack_data(packed_t &packed, const auto &data)
{
	const uint8_t *bytes = (const uint8_t *)&data;
	for (unsigned i = 0; i < sizeof(data); ++i) {
		packed.push_back(bytes[i]);
	}
}

static const std::string
type2string(const Type &type)
{
	std::string s;
	switch (type)
	{
		case Type::BOOL:
		{
			s = "bool";
			break;
		}
		case Type::NUMBER:
		{
			s = "number";
			break;
		}
		case Type::STRING:
		{
			s = "string";
			break;
		}
		case Type::NULLPTR:
		{
			s = "null";
			break;
		}
		case Type::DESC:
		{
			s = "descriptor";
			break;
		}
		case Type::TREE:
		{
			s = "descriptor";
			break;
		}
		default:
		{
			s = "array";
			break;
		}
	}
	return s;
}

Pair::Pair(const std::string &name)
	: _name{name}
	, _parent{nullptr}
{}

Pair::~Pair()
{}

const std::string &
Pair::name() { return _name; }

size_t
Pair::size() const
{
	return sizeof(nvtpair_header);
}

bool
Pair::is_array() const
{
	return false;
}

void
Pair::get(bool &)
{
	std::stringstream ss;
	ss << "Getting bool not implemented for type " << type2string(type());
	ss << " and name " << name();
	throw std::invalid_argument(ss.str());
}

void
Pair::get(uint64_t &)
{
	std::stringstream ss;
	ss << "Getting uint64_t not implemented for type " << type2string(type());
	ss << " and name " << name();
	throw std::invalid_argument(ss.str());
}

void
Pair::get(std::string &)
{
	std::stringstream ss;
	ss << "Getting std::string not implemented for type " << type2string(type());
	ss << " and name " << name();
	throw std::invalid_argument(ss.str());
}

void
Pair::get(int64_t &)
{
	std::stringstream ss;
	ss << "Getting int64_t not implemented for type " << type2string(type());
	ss << " and name " << name();
	throw std::invalid_argument(ss.str());
}

void
Pair::set(const bool &)
{
	std::stringstream ss;
	ss << "Setting bool not implemented for type " << type2string(type());
	ss << " and name " << name();
	throw std::invalid_argument(ss.str());
}

void
Pair::set(const int &)
{
	std::stringstream ss;
	ss << "Setting int not implemented for type " << type2string(type());
	ss << " and name " << name();
	throw std::invalid_argument(ss.str());
}

void
Pair::set(const uint64_t &)
{
	std::stringstream ss;
	ss << "Setting uint64_t not implemented for type " << type2string(type());
	ss << " and name " << name();
	throw std::invalid_argument(ss.str());
}

void
Pair::set(const char *)
{
	std::stringstream ss;
	ss << "Setting char * not implemented for type " << type2string(type());
	ss << " and name " << name();
	throw std::invalid_argument(ss.str());
}

void
Pair::set(const std::string &)
{
	std::stringstream ss;
	ss << "Setting std::string not implemented for type " << type2string(type());
	ss << " and name " << name();
	throw std::invalid_argument(ss.str());
}

void
Pair::set(const int64_t &)
{
	std::stringstream ss;
	ss << "Setting int64_t not implemented for type " << type2string(type());
	ss << " and name " << name();
	throw std::invalid_argument(ss.str());
}

void
Pair::parent(Pair *p)
{
	_parent = p;
}

Bool::Bool(const std::string &name, const bool &value)
	: Pair(name)
	, _value{value}
{}

size_t
Bool::size() const
{
	size_t size = Pair::size();
	size += sizeof(_value);
	size += _name.size() + 1;
	return size;
}

size_t
Bool::data_size() const
{
	return sizeof(_value);
}

Type
Bool::type() const { return Type::BOOL; }

uint8_t
Bool::nvtype() const { return NV_TYPE_BOOL; }

void
Bool::get(bool &value)
{
	value = _value;
}

void
Bool::set(const bool &value)
{
	_value = value;
}

bool
Bool::pack(packed_t &data)
{
	pack_data(data, (uint8_t)NV_TYPE_BOOL);
	pack_data(data, (uint16_t)(_name.size() + 1));
	pack_data(data, (uint64_t)sizeof(_value));
	pack_data(data, (uint64_t)0);
	pack_data(data, _name);
	pack_data(data, _value);
	return true;
}

bool
Bool::pack_raw(packed_t &data)
{
	pack_data(data, _value);
	return true;
}


Number::Number(const std::string &name, const uint64_t &value)
	: Pair(name)
	, _value{value}
{}

size_t
Number::size() const
{
	size_t size = Pair::size();
	size += sizeof(_value);
	size += _name.size() + 1;
	return size;
}

size_t
Number::data_size() const
{
	return sizeof(_value);
}

Type
Number::type() const { return Type::NUMBER; }

uint8_t
Number::nvtype() const { return NV_TYPE_NUMBER; }

void
Number::get(uint64_t &value)
{
	value = _value;
}

void
Number::set(const int &value)
{
	_value = value;
}

void
Number::set(const uint64_t &value)
{
	_value = value;
}

bool
Number::pack(packed_t &data)
{
	pack_data(data, (uint8_t)NV_TYPE_NUMBER);
	pack_data(data, (uint16_t)(_name.size() + 1));
	pack_data(data, (uint64_t)sizeof(_value));
	pack_data(data, (uint64_t)0);
	pack_data(data, _name);
	pack_data(data, _value);
	return true;
}

bool
Number::pack_raw(packed_t &data)
{
	pack_data(data, _value);
	return true;
}


String::String(const std::string &name, const std::string &value)
	: Pair(name)
	, _value{value}
{}

size_t
String::size() const
{ 
	size_t size = Pair::size();
	size += _value.size() + 1;
	size += _name.size() + 1;
	return size;
}

size_t
String::data_size() const
{
	return _value.size() + 1;
}

Type
String::type() const { return Type::STRING; }

uint8_t
String::nvtype() const { return NV_TYPE_STRING; }

void
String::get(std::string &value)
{
	value = _value;
}

void
String::set(const char *value)
{
	_value = value;
}

void
String::set(const std::string &value)
{
	_value = value;
}

bool
String::pack(packed_t &data)
{
	pack_data(data, (uint8_t)NV_TYPE_STRING);
	pack_data(data, (uint16_t)(_name.size() + 1));
	pack_data(data, (uint64_t)_value.size() + 1);
	pack_data(data, (uint64_t)0);
	pack_data(data, _name);
	pack_data(data, _value);
	return true;
}

bool
String::pack_raw(packed_t &data)
{
	pack_data(data, _value);
	return true;
}


Null::Null(const std::string &name)
	: Pair(name)
{}

size_t
Null::size() const
{
	size_t size = Pair::size();
	size += _name.size() + 1;
	return size;
}

size_t
Null::data_size() const
{
	return sizeof(nullptr);
}

Type
Null::type() const { return Type::NULLPTR; }

uint8_t
Null::nvtype() const { return NV_TYPE_NULL; }

bool
Null::pack(packed_t &data)
{
	pack_data(data, (uint8_t)NV_TYPE_NULL);
	pack_data(data, (uint16_t)(_name.size() + 1));
	pack_data(data, (uint64_t)0);
	pack_data(data, (uint64_t)0);
	pack_data(data, _name);
	return true;
}

bool
Null::pack_raw(packed_t &)
{
	return true;
}


Descriptor::Descriptor(const std::string &name, const int64_t &value)
	: Pair(name)
	, _value{value}
{}

size_t
Descriptor::size() const { return sizeof(_value); }

size_t
Descriptor::data_size() const { return sizeof(_value); }

Type
Descriptor::type() const { return Type::DESC; }

uint8_t
Descriptor::nvtype() const { return NV_TYPE_DESCRIPTOR; }

void
Descriptor::get(int64_t &value)
{
	value = _value;
}

void
Descriptor::set(const int &value)
{
	_value = value;
}

void
Descriptor::set(const int64_t &value)
{
	_value = value;
}

bool
Descriptor::pack(packed_t &)
{
	return true;
}

bool
Descriptor::pack_raw(packed_t &)
{
	return true;
}


Tree::Tree(const std::string &name)
	: Pair(name)
	, _index{0}
{}

size_t
Tree::size() const
{
	size_t s = sizeof(nvtpair_header);

	for (const auto &pair : _value)
	{
		s += pair.second->size();
		if (pair.second->type() == Type::TREE) {
			s += sizeof(nvtree_header) + pair.second->name().size() + 1;
		}
	}
	return s;
}

size_t
Tree::data_size() const
{
	return 0;
}

void
Tree::add(Pair *pair)
{
	if (pair == nullptr) {
		throw std::invalid_argument("Pair pointer is null");
	}
	auto &name = pair->name();
	if (name == "") {
		return;
	}
	auto *p = remove(name);
	if (p != nullptr)
	{
		delete p;
	}
	_value[name] = pair;
	pair->parent(this);
}

Pair *
Tree::remove(const std::string &name)
{
	Pair *pair = nullptr;
	auto i = _value.find(name);
	if (i != _value.end())
	{
		pair = i->second;
		_value.erase(i);
	}
	return pair;
}

bool
Tree::pack(packed_t &data)
{
	if (_parent != nullptr) {
		pack_data(data, (uint8_t)NV_TYPE_NVLIST);
		pack_data(data, (uint16_t)(_name.size() + 1));
		pack_data(data, (uint64_t)size());
		pack_data(data, (uint64_t)0);
		pack_data(data, _name);
	}
	for (const auto &i : header) {
		data.push_back(i); // magic and version
	}
	data.push_back(0); // flags
	pack_data(data, (uint64_t)0); // descriptors
	_index = data.size();
	pack_data(data, (uint64_t)0); // size

	for (const auto &item : _value) {
		item.second->pack(data);
		if (item.second->type() == Type::TREE) {
			pack_data(data, (uint8_t)0xff);
			pack_data(data, (uint16_t)1);
			pack_data(data, (uint64_t)0);
			pack_data(data, (uint64_t)0);
			pack_data(data, false);
		}
	}
	if (_parent == nullptr) {
		pack_size(data);
	}
	return true;
}

bool
Tree::pack_raw(packed_t &)
{
	return true;
}

bool
Tree::pack_size(packed_t &packed)
{
	Tree *t;
	const uint64_t size = packed.size() - _index - sizeof(uint64_t);
	const uint8_t *bytes = (const uint8_t *)&size;
	for (unsigned i = 0; i < sizeof(size); ++i) {
		packed[_index + i] = bytes[i];
	}
	_index = INFINITY;
	for (auto &item : _value) {
		if (item.second->type() == Type::TREE) {
			t = (Tree *)item.second;
			t->pack_size(packed);
		}
	}
	return true;
}

bool
Tree::unpack(void *data, size_t size)
{
	return _unpack(data, size);
}

bool
Tree::_unpack(void *&data, size_t &size)
{
	nvtree_header *thead = nullptr;
	nvtpair_header *phead = nullptr;
	const char *name = nullptr;

	if (data == nullptr) {
		return false;
	}
	if (size < sizeof(nvtree_header)) {
		return false;
	}
	offset_read(data, size, thead);
	if (thead->magic != header[0]) {
		return false;
	}
	if (thead->version != 0) {
		return false;
	}

	_value.clear();
	while (size > 0) {
		offset_read(data, size, phead);
		if (phead->namesize > 0) {
			name = (char *)data;
			data = ((uint8_t *)data) + phead->namesize;
			size -= phead->namesize;
		} else {
			name = "";
		}
		switch (phead->type) {
			case NV_TYPE_BOOL: {
				bool *value = nullptr;
				offset_read(data, size, value);
				add(new Bool(name, *value));
				break;
			}
			case NV_TYPE_NULL: {
				add(new Null(name));
				break;
			}
			case NV_TYPE_NUMBER: {
				uint64_t *value = nullptr;
				offset_read(data, size, value);
				add(new Number(name, *value));
				break;
			}
			case NV_TYPE_STRING: {
				char *value = (char *)data;
				size_t s = strlen(value) + 1;
				data = (void *)((uint8_t *)(data) + s);
				size -= s;
				add(new String(name, value));
				break;
			}
			case NV_TYPE_BOOL_ARRAY: {
				auto *arr = new Array<Bool>(name);
				bool *value = nullptr;
				for (uint64_t i = 0; i < phead->nitems; ++i) {
					offset_read(data, size, value);
					arr->add(new Bool("", *value));
				}
				add(arr);
				break;
			}
			case NV_TYPE_NUMBER_ARRAY: {
				auto *arr = new Array<Number>(name);
				uint64_t *value = nullptr;
				for (uint64_t i = 0; i < phead->nitems; ++i) {
					offset_read(data, size, value);
					arr->add(new Number("", *value));
				}
				add(arr);
				break;
			}
			case NV_TYPE_STRING_ARRAY: {
				auto *arr = new Array<String>(name);
				char *value = nullptr;
				size_t s = 0;
				for (uint64_t i = 0; i < phead->nitems; ++i) {
					s = strlen(value) + 1;
					data = (void *)((uint8_t *)(data) + s);
					size -= s;
					arr->add(new String("", value));
				}
				add(arr);
				break;
			}
			case NV_TYPE_NVLIST_ARRAY: {
				Tree *t = nullptr;
				auto *arr = new Array<Tree>(name);
				for (uint64_t i = 0; i < phead->nitems; ++i) {
					t = new Tree();
					if (!t->_unpack(data, size)) {
						return false;
					}
					arr->add(new Tree(""));
				}
				add(arr);
				break;
			}
			case NV_TYPE_NVLIST: {
				Tree *t = new Tree(name);
				if (!t->_unpack(data, size)) {
					return false;
				}
				add(t);
				break;
			}
			case 0xFE:
			case 0xFF: {
				return true;
			}
			default: {
				return false;
			}
		}
	}
	return true;
}

Pair *
Tree::find(const std::string &name)
{
	return _value[name];
}

Type
Tree::type() const { return Type::TREE; }

uint8_t
Tree::nvtype() const { return NV_TYPE_NVLIST; }

template <typename T>
Array<T>::Array(const std::string &name)
	: Pair(name)
{}

template <typename T>
size_t
Array<T>::size() const
{
	size_t size = Pair::size();
	size += _name.size() + 1;
	size += data_size();
	return size;
}

template <typename T>
size_t
Array<T>::data_size() const
{
	size_t size = 0;
	for (const auto &item : _value) {
		size += item->data_size();
	}
	return size;
}

template <typename T>
void
Array<T>::add(T *pair)
{
	_value.push_back(pair);
	pair->parent(this);
}

template <typename T>
T *
Array<T>::remove(const size_t &index)
{
	T *pair = nullptr;
	if (index >= _value.size()) { return nullptr; }
	pair = _value[index];
	_value.erase(_value.begin() + index);
	return pair;
}

template <typename T>
Type
Array<T>::type() const
{
	if (typeid(T) == typeid(Bool)) {
		return Type::ARRAY_BOOL;
	}
	if (typeid(T) == typeid(Number)) {
		return Type::ARRAY_NUMBER;
	}
	if (typeid(T) == typeid(String)) {
		return Type::ARRAY_STRING;
	}
	if (typeid(T) == typeid(Tree)) {
		return Type::ARRAY_TREE;
	}
	return Type::ARRAY_DESC;
}

template <typename T>
uint8_t
Array<T>::nvtype() const
{
	if (typeid(T) == typeid(Bool)) {
		return NV_TYPE_BOOL_ARRAY;
	}
	if (typeid(T) == typeid(Number)) {
		return NV_TYPE_NUMBER_ARRAY;
	}
	if (typeid(T) == typeid(String)) {
		return NV_TYPE_STRING_ARRAY;
	}
	if (typeid(T) == typeid(Tree)) {
		return NV_TYPE_NVLIST_ARRAY;
	}
	return NV_TYPE_DESCRIPTOR_ARRAY;
}

template <typename T>
Pair *
Array<T>::operator [] (const size_t &index)
{
	if (index >= _value.size()) { return nullptr; }
	return _value[index];
}

template <typename T>
bool
Array<T>::is_array() const
{
	return true;
}

template <typename T>
bool
Array<T>::pack(packed_t &data)
{
	T t;
	pack_data(data, nvtype());
	pack_data(data, (uint16_t)(_name.size() + 1));
	pack_data(data, (uint64_t)(t.data_size() * _value.size()));
	pack_data(data, (uint64_t)_value.size());
	pack_data(data, _name);
	if (t.type() == Type::TREE) {
		for (const auto &item: _value) {
			item->pack_raw(data);
		}
	} else {
		for (const auto &item: _value) {
			item->pack_raw(data);
			pack_data(data, (uint8_t)0xfe);
			pack_data(data, (uint16_t)1);
			pack_data(data, (uint64_t)0);
			pack_data(data, (uint64_t)0);
			pack_data(data, false);
		}
	}
	return true;
}

template <typename T>
bool
Array<T>::pack_raw(packed_t &)
{
	return true;
}

template class Array<Bool>;
template class Array<Number>;
template class Array<String>;
template class Array<Descriptor>;
template class Array<Tree>;
}
