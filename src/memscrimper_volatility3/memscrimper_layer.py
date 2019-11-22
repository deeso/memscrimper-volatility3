from memscrimper_parser.interface import Memscrimper
import threading
import logging

from typing import Any, Dict, IO, List, Optional, Union

from volatility.framework import exceptions, interfaces, constants
from volatility.framework.configuration import requirements
from volatility.framework.layers.physical import DummyLock

vollog = logging.getLogger(__name__)

class MemscrimperFormatException(exceptions.LayerException):
    pass
class MemscrimperConfigException(exceptions.LayerException):
    pass

class MemscrimperLayer(interfaces.layers.DataLayerInterface):
    priority = 4
    LOCATION = '_location'
    PRELOAD = '_preload'
    REFERENCE = '_reference'
    ANALYZE = '_analyze'
    OTHERS = '_others'

    SINGLE_LOCATION = 'automagic.LayerStacker.single_location'
    PLUGIN_MEMSCRIMPER_NON_EXISTENT = "BOOOOONEYBOOOONDOCOGLE"

    MEMSCRIMPER_LAYER = 'memscrimper_layer'
    A_REFERENCE = 'reference'
    A_SOURCE = 'source'

    PLUGIN_MEMSCRIMPER_LAYER_REFERENCE = "MemscrimperLayer.reference"
    PLUGIN_MEMSCRIMPER_LAYER_LOCATION = "MemscrimperLayer.location"
    PLUGIN_MEMSCRIMPER_LAYER_PRELOAD = "MemscrimperLayer.preload"
    PLUGIN_MEMSCRIMPER_LAYER_ANALYZE = "MemscrimperLayer.analyze"
    PLUGIN_MEMSCRIMPER_LAYER_OTHERS = "MemscrimperLayer.diffs"
    PLUGIN_STACK_FILELAYER_LOCATION = '.FileLayer.location'
    PATH_KEYS = [
        PLUGIN_MEMSCRIMPER_LAYER_REFERENCE,
        PLUGIN_MEMSCRIMPER_LAYER_LOCATION,
        PLUGIN_STACK_FILELAYER_LOCATION,
        PLUGIN_MEMSCRIMPER_LAYER_PRELOAD,
        PLUGIN_MEMSCRIMPER_LAYER_ANALYZE,
        PLUGIN_MEMSCRIMPER_LAYER_OTHERS
    ]

    REQUIRED_PATH_KEYS = {
        PLUGIN_MEMSCRIMPER_LAYER_REFERENCE: REFERENCE,
        PLUGIN_MEMSCRIMPER_LAYER_LOCATION: LOCATION,
        PLUGIN_STACK_FILELAYER_LOCATION: LOCATION,
        PLUGIN_MEMSCRIMPER_LAYER_PRELOAD: PRELOAD,
        PLUGIN_MEMSCRIMPER_LAYER_ANALYZE: ANALYZE,
        PLUGIN_MEMSCRIMPER_LAYER_OTHERS: OTHERS
    }
    REQUIRED_KEYS = set(REQUIRED_PATH_KEYS.values())

    header_structure = "<4s"
    HEADER_SIZE = 5
    MAGIC = b"MBCR\x00"

    LAYERS = ['memory', 'primary', 'primary2']
    FUNCTIONS = ['read', '_get_valid_table', 'hash', '_calculate_optional_header_lengths']
    CACHE_CLEAR = 'cache_clear'

    def clear_layer_caches(self):
        self.memscrimper_interface.msb.page_data = {}
        for layer_name in self.LAYERS:
            layer = self.context.layers.get(layer_name, None)
            if layer is None:
                continue
            for fn_name in self.FUNCTIONS:
                if hasattr(layer, fn_name) and \
                    hasattr(getattr(layer, fn_name), self.CACHE_CLEAR):
                    fn = getattr(layer, fn_name)
                    vollog.debug("Clearing lru_cache for: {}.{}".format(layer_name, fn_name))
                    fn.cache_clear()

        try:
            vollog.debug("Clearing lru_cache for: volatility.framework.symbols.windows.extensions.POOL_HEADE")
            from volatility.framework.symbols.windows.extensions import POOL_HEADER
            vollog.debug("Loaded: volatility.framework.symbols.windows.extensions.POOL_HEADE")
            if hasattr(POOL_HEADER, '_calculate_optional_header_lengths') and \
                    hasattr(POOL_HEADER._calculate_optional_header_lengths, self.CACHE_CLEAR):
                POOL_HEADER._calculate_optional_header_lengths.cache_clear()
            vollog.debug("Cleared lru_cache for: volatility.framework.symbols.windows.extensions.POOL_HEADE")
        except:
            vollog.debug("Failed to clear lru_cache for: volatility.framework.symbols.windows.extensions.POOL_HEADE")


    def set_reference_dump_type(self):
        self._analyze = self.A_REFERENCE
        self.memscrimper_interface = self._main_scimper
        self._scrimper = self._main
        num_pages = len(self.memscrimper_interface.msb.page_data)
        vollog.debug("Performed {} reads".format(self.reads_that_happened))
        self.reads_that_happened = 0
        vollog.debug("Setting reference dump Resetting pages, number of pages: {}".format(num_pages))
        self.clear_layer_caches()
        num_pages = len(self.memscrimper_interface.msb.page_data)
        vollog.debug("Setting reference dump Resetting pages, number of pages: {}".format(num_pages))
        self._location = self._main
        self.memscrimper_interface = self._main_scimper

    def set_source_dump_type(self, memscrimper_diff=None):
        if memscrimper_diff is None or memscrimper_diff not in self._memscrimpers:
            memscrimper_diff = self._main

        self._analyze = self.A_SOURCE
        self._scrimper = memscrimper_diff
        num_pages = len(self.memscrimper_interface.msb.page_data)
        vollog.debug("Performed {} reads".format(self.reads_that_happened))
        self.reads_that_happened = 0
        vollog.debug("Setting source dump Resetting pages, number of pages: {}".format(num_pages))
        self.clear_layer_caches()
        num_pages = len(self.memscrimper_interface.msb.page_data)
        vollog.debug("Setting source dump Resetting pages, number of pages: {}".format(num_pages))
        vollog.info("Setting source dump to: {}".format(memscrimper_diff))
        self.memscrimper_interface = self._memscrimpers.get(memscrimper_diff, None)
        if self.memscrimper_interface is None:
            ref_bytes = self._main_scimper.ref_bytes
            ms = self.load_memscrimper(memscrimper_diff, reference=self._reference, ref_bytes=ref_bytes, preload=True)
            self.memscrimper_interface = ms
            self._memscrimpers[memscrimper_diff] = ms

    def get_dump_type(self):
        return self._analyze

    def get_scrimper(self):
        return self._analyze

    def reset_pages(self):
        self.memscrimper_interface.reset_pages()

    @classmethod
    def load_from_json(cls, location) -> dict:
        try:
            my_dict = {}
            gk = set(cls.PATH_KEYS)
            import json
            header_data = open(location.strip("file:"), 'rb').read(8192)
            jd = json.loads(header_data)
            if jd.get('filetype', '') != 'Memscrimper':
                return {}
            for k, v in jd.items():
                pk = None
                for pk in gk:
                    ek = cls.REQUIRED_PATH_KEYS[pk]
                    if k.find(pk) > -1:
                        my_dict[ek] = v
                        break
                    pk = None
                if pk in gk:
                    gk.remove(pk)
                if len(gk) == 0:
                    break
            return my_dict
        except:
            return {}

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.StringRequirement(name='reference', optional=True),
                requirements.BooleanRequirement(name='location', optional=True),
                requirements.BooleanRequirement(name='preload', optional=True),
                # requirements.TranslationLayerRequirement(name='base_layer', optional=False),
                # requirements.TranslationLayerRequirement(name='meta_layer', optional=False),
                ]

    @classmethod
    def load_memscrimper(cls, location, reference=None, ref_bytes=None, preload=True):
        vollog.debug("Memscrimper '{}' not loaded, loading".format(location))
        if ref_bytes is not None:
            vollog.info("Loading Memscrimper with ref_bytes")
        elif reference is not None:
            vollog.info("Loading Memscrimper with reference {}".format(reference))
        ms = Memscrimper(src_fileobj=open(location, 'rb'),
                           ref_filename=reference, load=True,
                           ref_bytes=ref_bytes, load_ref_data=preload)
        vollog.debug("Successfully loaded the memscrimper")
        vollog.debug("Memscrimper compressed: {}".format(location))
        vollog.debug("Memscrimper reference: {}".format(reference))
        vollog.debug("Memscrimper uncompressed image size: {}".format(ms.uncompressed_size))
        vollog.debug("Memscrimper pages in file: {}".format(len(ms.changed_pages)))
        return ms

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:


        super().__init__(context, config_path = config_path, name = name, metadata = metadata)
        location = context.config.get(self.SINGLE_LOCATION)
        my_dict = self.load_from_json(location.strip('file:'))

        self._location = context.config.get(self.PLUGIN_MEMSCRIMPER_NON_EXISTENT, None)
        self._reference = context.config.get(self.PLUGIN_MEMSCRIMPER_NON_EXISTENT, None)
        self._preload = context.config.get(self.PLUGIN_MEMSCRIMPER_NON_EXISTENT, False)
        self._analyze = context.config.get(self.PLUGIN_MEMSCRIMPER_NON_EXISTENT, self.A_SOURCE)
        self._others = context.config.get(self.PLUGIN_MEMSCRIMPER_NON_EXISTENT, [])
        self._main = None
        self._memscrimpers = {}

        needed = [i for i in [self.LOCATION, self.REFERENCE] if i not in my_dict]
        if len(needed) > 0:
            raise MemscrimperConfigException("Could not find: {}".format(self.REQUIRED_PATH_KEYS.keys()))
        for k, v in my_dict.items():
            if isinstance(v, str):
                if v.find('file:///') > -1:
                    v = v.replace('file:///', '/')
                elif v.find('file://') > -1:
                    v = v.replace('file://', '/')
                elif v.find('file:/') > -1:
                    v = v.replace('file:/', '/')
            setattr(self, k, v)

        if self._location is None:
            raise MemscrimperFormatException("Invalid location provided")

        if self._reference is None:
            self._preload = False

        self._main = self._location
        self._main_scimper = None
        self.memscrimper_interface = None

        if len(self._others) > 1 and self._reference is not None:
            self._memscrimpers = {k: None for k in self._others}
            #FIXME probably better to use a memory mapped file, but this will work
            # for now
            ref_bytes = open(self._reference, 'rb').read()
            self._preload = True
            self._main_scimper = self.load_memscrimper(self._location, ref_bytes=ref_bytes, preload=True)
            self._memscrimpers[self._location] = self._main_scimper
            self._scrimper = self._main

        else:
            self._main_scimper = self.load_memscrimper(self._location, reference=self._reference, preload=True)
            self._memscrimpers[self._location] = self._main_scimper
            self._scrimper = self._main

        self.memscrimper_interface = self._main_scimper

        if self._analyze != self.A_SOURCE:
            self._analyze = self.A_REFERENCE

        self._size = self.memscrimper_interface.uncompressed_size
        self.reads_that_happened = 0
        self._lock = DummyLock()  # type: Union[DummyLock, threading.Lock]
        if constants.PARALLELISM == constants.Parallelism.Threading:
            self._lock = threading.Lock()

    @property
    def all_diffs(self):
        return sorted(set(self._others))

    @property
    def compressed(self) -> str:
        return self._location

    @property
    def location(self) -> str:
        return self._location

    @property
    def reference(self) -> str:
        return self._reference

    @property
    def preload(self) -> str:
        return self._preload

    @property
    def maximum_address(self) -> int:
        return self.memscrimper_interface.maximum_address

    @property
    def minimum_address(self) -> int:
        return 0

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return self.memscrimper_interface.is_valid(offset, length)

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads from the file at offset for length."""
        if not self.is_valid(offset, length):
            invalid_address = offset
            if self.minimum_address < offset <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(self.name, invalid_address,
                                                     "Offset outside of the buffer boundaries")
        self.reads_that_happened += 1
        try:
            with self._lock:
                if self._analyze == self.A_SOURCE:
                    data = self.memscrimper_interface.vol_read(offset, length, source=True, force_reload=True)
                else:
                    data = self.memscrimper_interface.vol_read(offset, length, source=False,force_reload=True)
        except:
            import traceback
            vollog.critical(traceback.format_exc())

        if len(data) < length:
            if pad:
                data += (b"\x00" * (length - len(data)))
            else:
                raise exceptions.InvalidAddressException(
                    self.name, offset + len(data), "Could not read sufficient bytes from the " + self.name + " file")
        return data

    def write(self, offset: int, data: bytes) -> None:
        """Writes to the file.

        This will technically allow writes beyond the extent of the file
        """
        if not self.is_valid(offset, len(data)):
            invalid_address = offset
            if self.minimum_address < offset <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(self.name, invalid_address,
                                                     "Data segment outside of the " + self.name + " file boundaries")
        with self._lock:
            self.memscrimper_interface.write(offset, data)


    def __getstate__(self) -> Dict[str, Any]:
        """Do not store the open _file_ attribute, our property will ensure the
        file is open when needed.

        This is necessary for multi-processing
        """
        # self.__dict__['memscrimper_interface'] = self.memscrimper_interface.__getstate__()
        return self.__dict__

    def destroy(self) -> None:
        """Closes the file handle."""
        self.memscrimper_interface.destroy()

    def _load_segments(self):
        pass

    @classmethod
    def _check_header(cls, base_layer: interfaces.layers.DataLayerInterface, offset: int = 0) -> bool:
        header_data = None
        # try:
        try:
            import json
            location = base_layer.config["location"]
            header_data = open(location.strip("file:"), 'rb').read(8192)
            jd = json.loads(header_data)
            if jd.get('filetype', '') == 'Memscrimper':
                return True
        except:
            return False
        # except exceptions.InvalidAddressException:
        #     raise MemscrimperFormatException(base_layer.name,
        #                               "Offset 0x{:0x} does not exist within the base layer".format(offset))

        if header_data != cls.MAGIC:
            return False
            # raise MemscrimperFormatException(base_layer.name, "Bad magic 0x{:x} at file offset 0x{:x}".format(magic, offset))

        return True

    @property
    def _file(self) -> IO[Any]:
        """Property to prevent the initializer storing an unserializable open
        file (for context cloning)"""
        # FIXME: Add "+" to the mode once we've determined whether write mode is enabled
        mode = "rb"
        self._file_ = self._file_ or self._accessor.open(self._location, mode)
        return self._file_

class MemscrimperStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 4

    @classmethod
    def stack(cls,
              context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: constants.ProgressCallback = None) -> Optional[
        interfaces.layers.DataLayerInterface]:

        if not MemscrimperLayer._check_header(context.layers[layer_name]):
            raise MemscrimperFormatException("Invalid Memscrimper Format")

        new_name = context.layers.free_layer_name("MemscrimperLayer")
        context.config[interfaces.configuration.path_join(new_name, "base_layer")] = layer_name
        return MemscrimperLayer(context, new_name, new_name)
