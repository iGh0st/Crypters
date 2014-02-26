class ResourceManager  
{
public:
	ResourceManager();
	virtual ~ResourceManager();

public:
	static void RunFromMemory(unsigned char* pImage,char* pPath);
	static unsigned char* GetResource(int resourceId, char* resourceString, unsigned long* dwSize);
};